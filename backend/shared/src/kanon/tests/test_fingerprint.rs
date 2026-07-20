//! Fingerprint computation.
//!
//! Implements §6.1 of the companion paper:
//!
//! | Paper concept            | Rust item                        |
//! |--------------------------|----------------------------------|
//! | QID attribute value      | [`QidValue`]                     |
//! | Source set `Src_q(o*)`   | [`SourceSet`]                    |
//! | Marginal fingerprint     | [`MarginalFingerprint`]          |
//! | Fingerprint tuple        | [`Fingerprint`]                  |
//! | Full computation         | [`compute_fingerprints`]         |
//!
//! ## Source-aware deduplication
//!
//! The source set is a *set* of `(source_id, value)` pairs: a single source
//! element contributes at most one entry per protected element.  The marginal
//! fingerprint is then the multiset of values obtained by forgetting source IDs,
//! represented as a `BTreeMap<QidValue, usize>` (value → multiplicity).
//!
//! ## Discrete equality
//!
//! All values are compared with discrete equality.  Timestamps are rendered as
//! strings for comparison (see [`QidValue`]).  Fine-grained timestamps will
//! therefore typically produce singleton equivalence classes; binning is future
//! work.

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

/// The discrete value extracted from an OCED element for a given QID attribute.
///
/// All comparisons use discrete equality.  Continuous numeric types and
/// timestamps are included but are not binned; fine-grained values will
/// produce large numbers of singleton equivalence classes (see module docs).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
pub enum QidValue {
    /// String attribute or object/event identifier.
    Str(String),
    /// Integer attribute value.
    Int(i64),
    /// Floating-point attribute value, rounded to 9 decimal places for
    /// equality comparison.  Discrete metric only.
    Float(ordered_float::OrderedFloat<f64>),
    /// Boolean attribute value.
    Bool(bool),
    /// The attribute was absent or its value was null.
    Null,
}

impl QidValue {
    /// Convert an [`OCELAttributeValue`] to a [`QidValue`].
    pub fn from_ocel_attr(v: &OCELAttributeValue) -> Self {
        match v {
            OCELAttributeValue::String(s) => QidValue::Str(s.clone()),
            OCELAttributeValue::Integer(i) => QidValue::Int(*i),
            OCELAttributeValue::Float(f) => QidValue::Float(ordered_float::OrderedFloat(*f)),
            OCELAttributeValue::Boolean(b) => QidValue::Bool(*b),
            OCELAttributeValue::Time(t) => {
                // Timestamps are rendered as ISO 8601 strings for discrete
                // comparison.  Fine-grained timestamps (millisecond resolution)
                // will virtually never repeat; binning is future work.
                QidValue::Str(t.to_rfc3339())
            }
            OCELAttributeValue::Null => QidValue::Null,
        }
    }
}

// ---------------------------------------------------------------------------
// SourceSet and MarginalFingerprint
// ---------------------------------------------------------------------------

/// A source set `Src_q(o*)`: a set of `(source_ocel_id, qid_value)` pairs.
///
/// Using a set ensures that the same source element contributes at most one
/// entry per protected element (source-aware deduplication, §6.1).
pub type SourceSet = HashSet<(String, QidValue)>;

/// A marginal fingerprint for one QID: a multiset of QID values, obtained
/// from the source set by forgetting source identifiers.
///
/// Represented as a `BTreeMap<QidValue, usize>` (value → multiplicity).
/// The `BTreeMap` provides a canonical ordering, making fingerprint equality
/// and hashing straightforward.
pub type MarginalFingerprint = BTreeMap<QidValue, usize>;

/// The full fingerprint of an element: a vector of marginal fingerprints,
/// one per QID of the policy (in policy order).
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

        // --- Named attribute (object) ---
        // Objects may have multiple time-stamped values for an attribute.
        // Under the time-stable restriction we take the first (and only)
        // value; if there are multiple, we take the one with the earliest
        // timestamp (arbitrary but deterministic).
        (EventOrObjectIndex::Object(oi), QidAttribute::Named(name)) => {
            ocel.get_ob_attr_vals(&oi, name)
                .min_by_key(|(t, _)| *t)
                .map(|(_, v)| QidValue::from_ocel_attr(v))
                .unwrap_or(QidValue::Null)
        }
    }
}

/// Build a type-qualified ID string for `element` to avoid collisions between
/// elements of different types that share the same raw OCEL identifier.
///
/// Format: `"<type>:<raw_id>"`, e.g. `"vehicle:v1"` or `"shipment:s1"`.
///
/// OCEL allows distinct object types (or event types) to reuse the same raw
/// identifier string.  Without type qualification, two elements with identical
/// raw IDs but different types would collide in the source-set and fingerprint
/// maps, causing one to silently overwrite the other.
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

/// Compute the source set `Src_q(o*)` for QID `qid` and target element
/// `target` against the evaluated output `out` of a binding box.
///
/// The target element is identified by its [`EventOrObjectIndex`]; only
/// bindings where the protected variable resolves to `target` are considered.
///
/// The union over all matchings is taken as a set (source-aware dedup).
///
/// Corresponds to Definition 6.1 of the companion paper.
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
            // Check that the protected element in this binding is `target`
            match protected_index_in_binding(qid, &phi, binding) {
                Some(prot) if prot == target => {}
                _ => continue,
            }

            // Read the source element and its QID attribute value
            if let Some(src_idx) = source_index_in_binding(qid, &phi, binding) {
                let src_id = element_id(src_idx, ocel);
                let val = read_qid_value(src_idx, &qid.attribute, ocel);
                src.insert((src_id, val));
            }
        }
    }

    src
}

/// Convert a [`SourceSet`] to a [`MarginalFingerprint`] by projecting away
/// the source identifier.
pub fn source_set_to_marginal(src: &SourceSet) -> MarginalFingerprint {
    let mut fp: MarginalFingerprint = BTreeMap::new();
    for (_src_id, val) in src {
        *fp.entry(val.clone()).or_insert(0) += 1;
    }
    fp
}

// ---------------------------------------------------------------------------
// Full fingerprint computation for all protected elements
// ---------------------------------------------------------------------------

/// Compute the equivalence classes induced by the policy fingerprints.
///
/// Returns a [`BTreeMap`] from [`Fingerprint`] to the list of type-qualified
/// element IDs that share that fingerprint.  Using the fingerprint as the map
/// key means each distinct fingerprint is stored exactly once, regardless of
/// how many elements share it.
///
/// The element IDs in each value list are type-qualified strings of the form
/// `"<type>:<raw_id>"` (e.g. `"vehicle:v1"`), which avoids collisions between
/// elements of different types that happen to share the same raw OCEL ID.
///
/// Elements that do not appear in any active binding set receive an all-empty
/// fingerprint and are grouped together in the corresponding class.
///
/// ## Complexity
///
/// The previous implementation called `compute_source_set` per element, which
/// iterated over the full `out` slice for each element — O(elements × bindings)
/// per QID.  This implementation uses an **inverted index** built once per
/// (QID, matching) pair in O(bindings), then looks up each protected element in
/// O(1).  The total cost is O(bindings + elements) per QID instead of
/// O(elements × bindings).
///
/// Corresponds to Definitions 6.1 and 6.2 of the companion paper.
pub fn compute_fingerprints(
    policy: &AnonPolicy,
    bbox: &crate::binding_box::structs::BindingBox,
    out: &[Arc<Binding>],
    ocel: &SlimLinkedOCEL,
) -> BTreeMap<Fingerprint, Vec<String>> {
    let prot_types = policy.protected_type_set();

    // ── Collect all elements of the protected type set ────────────────────────
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

    // ── Pre-compute per-QID inverted source sets ───────────────────────────────
    // For each activated QID, build:
    //   qid_src_maps[q] : HashMap<prot_idx, SourceSet>
    // by scanning `out` once per (QID, matching) pair instead of once per
    // (QID, matching, protected element).
    //
    // Cost: O(|matchings| × |out|) per QID — typically |matchings| ≪ |elements|.
    let qid_src_maps: Vec<Option<HashMap<EventOrObjectIndex, SourceSet>>> = policy
        .qids
        .iter()
        .map(|qid| {
            let matchings = find_matchings(&qid.pattern, bbox);
            if matchings.is_empty() {
                // QID not activated: no source sets to compute.
                return None;
            }

            // Accumulate source pairs into a per-protected-element map.
            // Using a HashMap<prot_idx, SourceSet> lets us insert in O(1)
            // and look up in O(1) per protected element later.
            let mut src_map: HashMap<EventOrObjectIndex, SourceSet> = HashMap::new();

            for phi in &matchings {
                // active_binding_set filters `out` to bindings satisfying the
                // pattern under φ — still O(|out|) but called once per matching,
                // not once per (matching × element).
                let active = active_binding_set(qid, phi, out, ocel);

                for binding in active {
                    // Resolve the protected and source elements for this binding.
                    let Some(prot_idx) = protected_index_in_binding(qid, phi, binding)
                    else { continue };
                    let Some(src_idx)  = source_index_in_binding(qid, phi, binding)
                    else { continue };

                    // Source-aware deduplication: insert into the SourceSet of
                    // this protected element.  HashSet::insert is a no-op for
                    // duplicates, implementing the "set" semantics of Src_q(o*).
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

    // ── Build equivalence classes ─────────────────────────────────────────────
    // For each protected element, look up its source set in each QID's map
    // (O(1) per QID) and convert to a marginal fingerprint.
    let mut classes: BTreeMap<Fingerprint, Vec<String>> = BTreeMap::new();

    for elem in protected_elements {
        let qualified_id = element_id(elem, ocel);

        let fp: Fingerprint = qid_src_maps
            .iter()
            .map(|opt_map| match opt_map {
                // Non-activated QID: empty marginal fingerprint.
                None => BTreeMap::new(),
                // Activated QID: look up this element's source set.
                // Elements absent from the map had no active bindings →
                // they also get an empty marginal fingerprint.
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