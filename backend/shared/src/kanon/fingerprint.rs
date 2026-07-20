//! Fingerprint computation. Implements §4.3.1 of the companion paper
//! (Definitions 9-10):
//!
//! | Paper concept                      | Rust item                |
//! |--------------------------------------|---------------------------|
//! | QID attribute value                 | [`QidValue`]              |
//! | Source set `Src_q(o*)` (Def. 9)     | [`SourceSet`]             |
//! | Marginal fingerprint (Def. 9)       | [`MarginalFingerprint`]   |
//! | Fingerprint tuple (Def. 10)         | [`Fingerprint`]           |
//! | Full computation                    | [`compute_fingerprints`]  |
//!
//! `SourceSet` is a *set* of `(source_id, value)` pairs (source-aware dedup:
//! one entry per source element). `MarginalFingerprint` forgets source IDs,
//! as a `BTreeMap<QidValue, usize>` (value → multiplicity). All comparisons
//! are discrete; timestamps are rendered as strings (see [`QidValue`]),
//! typically yielding singleton classes — binning is future work.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

use process_mining::core::event_data::object_centric::linked_ocel::{
    slim_linked_ocel::EventOrObjectIndex, LinkedOCELAccess, SlimLinkedOCEL,
};

use crate::binding_box::structs::Binding;

use crate::kanon::{
    activation::{
        active_binding_set, find_matchings, protected_index_in_binding, source_index_in_binding,
    },
    policy::{AnonPolicy, QidAttribute, QuasiIdentifier},
};

use process_mining::core::event_data::object_centric::OCELAttributeValue;

// ---------------------------------------------------------------------------
// QidValue
// ---------------------------------------------------------------------------

/// The discrete value read from an OCED element for a QID attribute
/// (discrete equality throughout; no binning, see module docs).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
pub enum QidValue {
    /// String attribute, or an object/event identifier.
    Str(String),
    /// Integer attribute.
    Int(i64),
    /// Float attribute (`OrderedFloat` for `Eq`/`Ord`).
    Float(ordered_float::OrderedFloat<f64>),
    /// Boolean attribute.
    Bool(bool),
    /// Attribute absent or null.
    Null,
}

impl QidValue {
    /// Converts an [`OCELAttributeValue`] to a [`QidValue`].
    pub fn from_ocel_attr(v: &OCELAttributeValue) -> Self {
        match v {
            OCELAttributeValue::String(s) => QidValue::Str(s.clone()),
            OCELAttributeValue::Integer(i) => QidValue::Int(*i),
            OCELAttributeValue::Float(f) => QidValue::Float(ordered_float::OrderedFloat(*f)),
            OCELAttributeValue::Boolean(b) => QidValue::Bool(*b),
            // Rendered as an RFC 3339 string for discrete comparison.
            OCELAttributeValue::Time(t) => QidValue::Str(t.to_rfc3339()),
            OCELAttributeValue::Null => QidValue::Null,
        }
    }
}

// ---------------------------------------------------------------------------
// SourceSet and MarginalFingerprint
// ---------------------------------------------------------------------------

/// `Src_q(o*)` (Def. 9): a set of `(source_ocel_id, qid_value)` pairs —
/// source-aware deduplication, one entry per source element.
pub type SourceSet = HashSet<(String, QidValue)>;

/// `fp_q(o*)` (Def. 9): `Src_q(o*)` with source IDs forgotten, as
/// `BTreeMap<QidValue, usize>` (value → multiplicity; canonical ordering).
pub type MarginalFingerprint = BTreeMap<QidValue, usize>;

/// `fp(o*)` (Def. 10): one [`MarginalFingerprint`] per QID, in policy order.
pub type Fingerprint = Vec<MarginalFingerprint>;

// ---------------------------------------------------------------------------
// Reading a QID attribute value from an element
// ---------------------------------------------------------------------------

/// Read the QID attribute value from `element` in `ocel`.
///
/// Returns [`QidValue::Null`] if the attribute is absent.
pub(crate) fn read_qid_value(
    element: EventOrObjectIndex,
    attr: &QidAttribute,
    ocel: &SlimLinkedOCEL,
) -> QidValue {
    match (element, attr) {
        // --- Id ---
        (EventOrObjectIndex::Event(ei), QidAttribute::Id) => {
            QidValue::Str(ocel.get_ev_id(&ei).to_string())
        }
        (EventOrObjectIndex::Object(oi), QidAttribute::Id) => {
            QidValue::Str(ocel.get_ob_id(&oi).to_string())
        }

        // --- Timestamp ---
        (EventOrObjectIndex::Event(ei), QidAttribute::Timestamp) => {
            QidValue::Str(ocel.get_ev_time(&ei).to_rfc3339())
        }
        (EventOrObjectIndex::Object(_), QidAttribute::Timestamp) => {
            // Objects do not have a single timestamp in OCED; return Null.
            QidValue::Null
        }

        // --- Named attribute (event) ---
        (EventOrObjectIndex::Event(ei), QidAttribute::Named(name)) => ocel
            .get_ev_attr_val(&ei, name)
            .map(QidValue::from_ocel_attr)
            .unwrap_or(QidValue::Null),

        // Object attrs may have several time-stamped values; take the
        // earliest (deterministic tie-break under the time-stable restriction).
        (EventOrObjectIndex::Object(oi), QidAttribute::Named(name)) => {
            ocel.get_ob_attr_vals(&oi, name)
                .min_by_key(|(t, _)| *t)
                .map(|(_, v)| QidValue::from_ocel_attr(v))
                .unwrap_or(QidValue::Null)
        }
    }
}

/// `"<type>:<raw_id>"` (e.g. `"vehicle:v1"`) — OCEL allows distinct types to
/// reuse the same raw ID, so plain IDs would collide across types.
pub(crate) fn element_id(element: EventOrObjectIndex, ocel: &SlimLinkedOCEL) -> String {
    match element {
        EventOrObjectIndex::Event(ei) => {
            let raw_id  = ocel.get_ev_id(&ei);
            let ev_type = ocel.get_ev_type_of(&ei); // &str, not Option<&OCELType>
            format!("{ev_type}:{raw_id}")
        }
        EventOrObjectIndex::Object(oi) => {
            let raw_id  = ocel.get_ob_id(&oi);
            let ob_type = ocel.get_ob_type_of(&oi); // &str, not Option<&OCELType>
            format!("{ob_type}:{raw_id}")
        }
    }
}

// ---------------------------------------------------------------------------
// Source-set computation
// ---------------------------------------------------------------------------

/// `Src_q(target)` (Definition 9): union over all matchings, restricted to
/// bindings whose protected variable resolves to `target`.
pub fn compute_source_set(
    qid: &QuasiIdentifier,
    target: EventOrObjectIndex,
    bbox: &crate::binding_box::structs::BindingBox,
    out: &[Arc<Binding>],
    ocel: &SlimLinkedOCEL,
) -> SourceSet {
    let mut src: SourceSet = HashSet::new();

    for phi in find_matchings(&qid.pattern, bbox) {
        let active = active_binding_set(qid, &phi, out, ocel);

        for binding in active {
            match protected_index_in_binding(qid, &phi, binding) {
                Some(prot) if prot == target => {}
                _ => continue,
            }

            if let Some(src_idx) = source_index_in_binding(qid, &phi, binding) {
                let src_id = element_id(src_idx, ocel);
                let val = read_qid_value(src_idx, &qid.attribute, ocel);
                src.insert((src_id, val));
            }
        }
    }

    src
}

/// `SourceSet` → `MarginalFingerprint`: forgets source identifiers.
pub fn source_set_to_marginal(src: &SourceSet) -> MarginalFingerprint {
    let mut fp: MarginalFingerprint = BTreeMap::new();
    for (_src_id, val) in src {
        *fp.entry(val.clone()).or_insert(0) += 1;
    }
    fp
}

/// Equivalence classes (Defs. 9-10): [`Fingerprint`] → type-qualified IDs
/// sharing it. Elements outside every active binding set get the all-empty
/// fingerprint and are grouped together.
///
/// ## Complexity
/// Builds an **inverted index** per (QID, matching) in O(bindings), then
/// looks up each protected element in O(1): O(bindings + elements) per QID,
/// instead of the naive O(elements × bindings) of calling
/// [`compute_source_set`] once per element.
pub fn compute_fingerprints(
    policy: &AnonPolicy,
    bbox: &crate::binding_box::structs::BindingBox,
    out: &[Arc<Binding>],
    ocel: &SlimLinkedOCEL,
) -> BTreeMap<Fingerprint, Vec<String>> {
    let prot_types = policy.protected_type_set();

    // All elements of the protected type set.
    let protected_elements: Vec<EventOrObjectIndex> = {
        let mut v = Vec::new();
        for ot in &prot_types {
            for ob_idx in ocel.get_obs_of_type(ot) {
                v.push(EventOrObjectIndex::Object(*ob_idx));
            }
            for ev_idx in ocel.get_evs_of_type(ot) {
                v.push(EventOrObjectIndex::Event(*ev_idx));
            }
        }
        v
    };

    // Per-QID inverted index: prot_idx → SourceSet, built in one pass over
    // `out` per (QID, matching) pair — O(|matchings| × |out|) per QID.
    let qid_src_maps: Vec<Option<HashMap<EventOrObjectIndex, SourceSet>>> = policy
        .qids
        .iter()
        .map(|qid| {
            let matchings = find_matchings(&qid.pattern, bbox);
            if matchings.is_empty() {
                return None; // QID not activated
            }

            let mut src_map: HashMap<EventOrObjectIndex, SourceSet> = HashMap::new();

            for phi in &matchings {
                let active = active_binding_set(qid, phi, out, ocel);

                for binding in active {
                    let Some(prot_idx) = protected_index_in_binding(qid, phi, binding)
                    else { continue };
                    let Some(src_idx)  = source_index_in_binding(qid, phi, binding)
                    else { continue };

                    // HashSet::insert is a no-op for duplicates: implements
                    // the source-aware "set" semantics of Src_q(o*).
                    let src_id = element_id(src_idx, ocel);
                    let val    = read_qid_value(src_idx, &qid.attribute, ocel);
                    src_map
                        .entry(prot_idx)
                        .or_default()
                        .insert((src_id, val));
                }
            }

            Some(src_map)
        })
        .collect();

    // Look up each protected element's source set per QID (O(1)) and convert
    // to a marginal fingerprint; absent ⟹ empty (non-activated or no active
    // bindings for this element).
    let mut classes: BTreeMap<Fingerprint, Vec<String>> = BTreeMap::new();

    for elem in protected_elements {
        let qualified_id = element_id(elem, ocel);

        let fp: Fingerprint = qid_src_maps
            .iter()
            .map(|opt_map| match opt_map {
                None => BTreeMap::new(),
                Some(src_map) => src_map
                    .get(&elem)
                    .map(source_set_to_marginal)
                    .unwrap_or_default(),
            })
            .collect();

        classes.entry(fp).or_default().push(qualified_id);
    }

    classes
}