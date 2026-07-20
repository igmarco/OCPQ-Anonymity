//! Anonymity-property evaluation, organised in four layers:
//!
//! ```text
//! build_context          → PolicyContext   (shared by all layers)
//!
//! LAYER 1 — Pointwise      eval_k/l/t(ctx, param) → K/L/TResult
//! LAYER 2 — Limits         find_k/l/t_max/min(ctx) → usize / Option<f64>
//! LAYER 3 — Risk           elements_at_risk, sensitive_values_at_risk
//! ```
//!
//! [`report::check_policy`] is the public entry point.
//!
//! ## Scope
//! Assumes [`BindingBox`] has **no constraints and no labels** (`debug_assert`
//! in [`build_context`]). Supporting structural constraints (§5 of the paper)
//! would require checking anonymity on the satisfied/violated subset of each
//! sign assignment `σ : Γ → {+, −}` *and* on the full output; k-anonymity and
//! l-diversity on the full set then follow automatically from both subsets,
//! but t-closeness does not inherit this way.
//!
//! ## t-closeness ground metric
//! Discrete only: `EMD = 1 − Σ_v min(P_local(v), P_global(v))`. Binning for
//! continuous attributes is future work.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

use process_mining::core::event_data::object_centric::linked_ocel::{
    LinkedOCELAccess, SlimLinkedOCEL,
};

use crate::binding_box::structs::{Binding, BindingBox};
use crate::kanon::{
    activation::qid_is_activated,
    fingerprint::{compute_fingerprints, Fingerprint, QidValue},
    policy::AnonPolicy,
    report::SensitiveAttrRisk,
};

// =============================================================================
// Shared base: PolicyContext
// =============================================================================

/// Base computations shared by all evaluation layers. Build once with
/// [`build_context`], pass to every layer.
pub struct PolicyContext {
    /// Fingerprint → type-qualified element IDs.
    pub class_map: BTreeMap<Fingerprint, Vec<String>>,
    /// Type-qualified element ID → sensitive-attribute tuple.
    pub sens_map: HashMap<String, Vec<QidValue>>,
    /// Global distribution of sensitive-value tuples (for t-closeness).
    pub global_dist: BTreeMap<Vec<QidValue>, usize>,
    /// Total protected elements (sum of class sizes).
    pub global_total: usize,
    /// IDs of activated QIDs.
    pub activated_qid_ids: Vec<String>,
    /// IDs of non-activated QIDs.
    pub non_activated_qid_ids: Vec<String>,
}

impl PolicyContext {
    /// `true` iff at least one QID was activated.
    pub fn policy_activated(&self) -> bool {
        !self.activated_qid_ids.is_empty()
    }
}

/// Builds the [`PolicyContext`] for `policy` against `bbox`'s evaluated
/// output. The only function touching the OCEL/binding output directly;
/// all other layers operate on the context alone.
///
/// # Panics (debug)
/// If `bbox` has constraints or labels (outside prototype scope).
pub fn build_context(
    policy: &AnonPolicy,
    bbox: &BindingBox,
    out: &[Arc<Binding>],
    ocel: &SlimLinkedOCEL,
) -> PolicyContext {
    debug_assert!(
        bbox.constraints.is_empty(),
        "build_context: BindingBox has {} constraint(s); not yet supported. \
         See module docs for the planned extension.",
        bbox.constraints.len()
    );
    debug_assert!(
        bbox.labels.is_empty(),
        "build_context: BindingBox has {} label(s); labels are ignored.",
        bbox.labels.len()
    );

    // Activated / non-activated QIDs
    let (activated_qid_ids, non_activated_qid_ids) = policy
        .qids
        .iter()
        .partition::<Vec<_>, _>(|qid| qid_is_activated(qid, bbox))
        .apply_both(|v| v.into_iter().map(|q| q.id.clone()).collect());

    // Equivalence classes
    let class_map = compute_fingerprints(policy, bbox, out, ocel);
    let global_total: usize = class_map.values().map(|v| v.len()).sum();

    // Sensitive-value map
    let all_ids: Vec<String> = class_map.values().flatten().cloned().collect();
    let sens_map = build_sensitive_map(policy, out, &all_ids, ocel);

    // Global distribution for t-closeness
    let global_dist: BTreeMap<Vec<QidValue>, usize> = {
        let mut d = BTreeMap::new();
        for sv in sens_map.values() {
            *d.entry(sv.clone()).or_insert(0) += 1;
        }
        d
    };

    PolicyContext {
        class_map,
        sens_map,
        global_dist,
        global_total,
        activated_qid_ids,
        non_activated_qid_ids,
    }
}

// =============================================================================
// Intermediate result types
// =============================================================================

/// Per-class result of k-anonymity evaluation.
#[derive(Debug, Clone)]
pub struct KClass {
    /// Type-qualified IDs of the elements in this class.
    pub members: Vec<String>,
    /// Whether this class satisfies k-anonymity (`members.len() >= k`).
    pub ok: bool,
}

/// Result of [`eval_k`].
#[derive(Debug, Clone)]
pub struct KResult {
    /// Per-class k-anonymity results, in the same order as
    /// [`PolicyContext::class_map`] (largest class first after sorting).
    pub classes: Vec<KClass>,
    /// Global conjunction: `true` iff every class satisfies k-anonymity.
    pub satisfied: bool,
    /// The k value this result was evaluated against.
    pub k: usize,
}

/// Per-class result of l-diversity evaluation.
#[derive(Debug, Clone)]
pub struct LClass {
    pub members: Vec<String>,
    /// The sensitive-value tuples of each member (parallel to `members`).
    pub sensitive_values: Vec<Vec<QidValue>>,
    /// Number of distinct sensitive-value tuples in this class.
    pub distinct_count: usize,
    pub ok: bool,
}

/// Result of [`eval_l`].
#[derive(Debug, Clone)]
pub struct LResult {
    pub classes: Vec<LClass>,
    pub satisfied: bool,
    pub l: usize,
}

/// Per-class result of t-closeness evaluation.
#[derive(Debug, Clone)]
pub struct TClass {
    pub members: Vec<String>,
    pub sensitive_values: Vec<Vec<QidValue>>,
    /// Discrete EMD between this class and the global distribution.
    /// `None` when there are no sensitive attributes.
    pub emd: Option<f64>,
    pub ok: bool,
}

/// Result of [`eval_t`].
#[derive(Debug, Clone)]
pub struct TResult {
    pub classes: Vec<TClass>,
    pub satisfied: bool,
    pub t: f64,
}

// =============================================================================
// Layer 1 — Pointwise evaluation
// =============================================================================

/// Evaluate k-anonymity for every equivalence class in `ctx`.
pub fn eval_k(ctx: &PolicyContext, k: usize) -> KResult {
    let mut classes: Vec<KClass> = ctx
        .class_map
        .values()
        .map(|members| {
            let mut members = members.clone();
            members.sort();
            let ok = members.len() >= k;
            KClass { members, ok }
        })
        .collect();

    // Largest class first for readability
    classes.sort_by(|a, b| b.members.len().cmp(&a.members.len()));

    let satisfied = classes.iter().all(|c| c.ok);
    KResult { classes, satisfied, k }
}

/// Evaluate l-diversity for every equivalence class in `ctx`.
pub fn eval_l(ctx: &PolicyContext, l: usize) -> LResult {
    let mut classes: Vec<LClass> = ctx
        .class_map
        .values()
        .map(|members| {
            let mut members = members.clone();
            members.sort();

            let sensitive_values: Vec<Vec<QidValue>> = members
                .iter()
                .map(|id| ctx.sens_map.get(id).cloned().unwrap_or_default())
                .collect();

            let distinct_count = sensitive_values
                .iter()
                .collect::<HashSet<_>>()
                .len();

            let ok = l == 0 || distinct_count >= l;
            LClass { members, sensitive_values, distinct_count, ok }
        })
        .collect();

    classes.sort_by(|a, b| b.members.len().cmp(&a.members.len()));
    let satisfied = classes.iter().all(|c| c.ok);
    LResult { classes, satisfied, l }
}

/// Evaluate t-closeness for every equivalence class in `ctx`.
pub fn eval_t(ctx: &PolicyContext, t: f64) -> TResult {
    let no_sensitive = ctx.global_dist.is_empty();

    let mut classes: Vec<TClass> = ctx
        .class_map
        .values()
        .map(|members| {
            let mut members = members.clone();
            members.sort();

            let sensitive_values: Vec<Vec<QidValue>> = members
                .iter()
                .map(|id| ctx.sens_map.get(id).cloned().unwrap_or_default())
                .collect();

            let (emd, ok) = if no_sensitive || t >= 1.0 {
                (None, true)
            } else {
                let e = discrete_emd(&sensitive_values, &ctx.global_dist, ctx.global_total);
                (Some(e), e <= t)
            };

            TClass { members, sensitive_values, emd, ok }
        })
        .collect();

    classes.sort_by(|a, b| b.members.len().cmp(&a.members.len()));
    let satisfied = classes.iter().all(|c| c.ok);
    TResult { classes, satisfied, t }
}

// =============================================================================
// Layer 2 — Limit analysis
// =============================================================================

/// The maximum k the data actually satisfies: the size of the smallest class.
/// Returns 0 when there are no protected elements.
pub fn find_k_max(ctx: &PolicyContext) -> usize {
    ctx.class_map
        .values()
        .map(|v| v.len())
        .min()
        .unwrap_or(0)
}

/// The maximum l the data actually satisfies: the minimum number of distinct
/// sensitive-value tuples across all classes.
/// Returns 0 when there are no classes or no sensitive attributes.
pub fn find_l_max(ctx: &PolicyContext) -> usize {
    ctx.class_map
        .values()
        .map(|members| {
            let tuples: HashSet<Vec<QidValue>> = members
                .iter()
                .map(|id| ctx.sens_map.get(id).cloned().unwrap_or_default())
                .collect();
            tuples.len()
        })
        .min()
        .unwrap_or(0)
}

/// The minimum discrete EMD across all classes: the most restrictive
/// t-closeness the data satisfies.
/// Returns `None` when there are no sensitive attributes.
pub fn find_t_min(ctx: &PolicyContext, t_result: &TResult) -> Option<f64> {
    if ctx.global_dist.is_empty() {
        return None;
    }
    t_result.classes.iter().filter_map(|c| c.emd).reduce(f64::min)
}

// =============================================================================
// Layer 3 — Risk analysis
// =============================================================================

/// Flat list of type-qualified element IDs that belong to a class violating
/// k-anonymity.  Empty when k-anonymity is satisfied.
pub fn elements_at_risk(k_result: &KResult) -> Vec<String> {
    k_result
        .classes
        .iter()
        .filter(|c| !c.ok)
        .flat_map(|c| c.members.iter().cloned())
        .collect()
}

/// For each sensitive attribute, the distinct values that appear in classes
/// violating l-diversity or t-closeness.
///
/// `l_result` and `t_result` must have been evaluated against the same
/// [`PolicyContext`].  `sensitive_attrs` is `policy.sensitive_attrs`.
pub fn sensitive_values_at_risk(
    l_result: &LResult,
    t_result: &TResult,
    sensitive_attrs: &[String],
) -> Vec<SensitiveAttrRisk> {
    // Collect classes violating l or t (by member set, to deduplicate)
    let violating_sensitive: Vec<&Vec<Vec<QidValue>>> = l_result
        .classes
        .iter()
        .filter(|c| !c.ok)
        .map(|c| &c.sensitive_values)
        .chain(
            t_result
                .classes
                .iter()
                .filter(|c| !c.ok)
                .map(|c| &c.sensitive_values),
        )
        .collect();

    sensitive_attrs
        .iter()
        .enumerate()
        .map(|(attr_idx, attr_name)| {
            let mut at_risk: Vec<QidValue> = violating_sensitive
                .iter()
                .flat_map(|class_svs| class_svs.iter())
                .filter_map(|tuple| tuple.get(attr_idx).cloned())
                .collect::<HashSet<_>>()
                .into_iter()
                .collect();
            at_risk.sort();
            SensitiveAttrRisk {
                attr_name: attr_name.clone(),
                at_risk_values: at_risk,
            }
        })
        .collect()
}

// =============================================================================
// Internal helpers
// =============================================================================

/// Type-qualified element ID → sensitive-attribute tuple, read directly from
/// the protected element via the OCEL attribute API (O(elements × |attrs|),
/// optimal for this access pattern; `_out` unused, kept for signature symmetry).
pub(crate) fn build_sensitive_map(
    policy: &AnonPolicy,
    _out: &[Arc<Binding>],
    elem_ids: &[String],
    ocel: &SlimLinkedOCEL,
) -> HashMap<String, Vec<QidValue>> {
    use crate::kanon::fingerprint::QidValue;

    elem_ids
        .iter()
        .map(|qualified_id| {
            // Strip "<type>:" prefix to get the raw OCEL identifier.
            let raw_id = qualified_id
                .splitn(2, ':')
                .nth(1)
                .unwrap_or(qualified_id.as_str());

            let tuple: Vec<QidValue> = if policy.sensitive_attrs.is_empty() {
                vec![]
            } else {
                // Resolve the element as object first, then as event.
                let ob_opt = ocel.get_ob_by_id(raw_id);
                let ev_opt = if ob_opt.is_none() {
                    ocel.get_ev_by_id(raw_id)
                } else {
                    None
                };

                policy
                    .sensitive_attrs
                    .iter()
                    .map(|attr| {
                        if let Some(ref ob) = ob_opt {
                            ocel.get_ob_attr_vals(ob, attr)
                                .next()
                                .map(|(_, v)| QidValue::from_ocel_attr(v))
                                .unwrap_or(QidValue::Null)
                        } else if let Some(ref ev) = ev_opt {
                            ocel.get_ev_attr_val(ev, attr)
                                .map(QidValue::from_ocel_attr)
                                .unwrap_or(QidValue::Null)
                        } else {
                            QidValue::Null
                        }
                    })
                    .collect()
            };

            (qualified_id.clone(), tuple)
        })
        .collect()
}

/// Discrete Earth Mover's Distance between a class distribution and the global
/// distribution.  Result is always in `[0, 1]`.
pub(crate) fn discrete_emd(
    class_sensitive: &[Vec<QidValue>],
    global_dist: &BTreeMap<Vec<QidValue>, usize>,
    global_total: usize,
) -> f64 {
    if class_sensitive.is_empty() || global_total == 0 {
        return 0.0;
    }

    let local_total = class_sensitive.len() as f64;
    let mut local_counts: BTreeMap<&Vec<QidValue>, usize> = BTreeMap::new();
    for sv in class_sensitive {
        *local_counts.entry(sv).or_insert(0) += 1;
    }

    let sum_min: f64 = local_counts
        .iter()
        .map(|(val, &lc)| {
            let p_local  = lc as f64 / local_total;
            let p_global = global_dist.get(*val).copied().unwrap_or(0) as f64
                / global_total as f64;
            p_local.min(p_global)
        })
        .sum();

    (1.0 - sum_min).clamp(0.0, 1.0)
}

// =============================================================================
// Helper: partition-and-map both sides
// =============================================================================

trait PartitionBothExt<T> {
    fn apply_both<U, F: Fn(Vec<T>) -> U>(self, f: F) -> (U, U);
}

impl<T> PartitionBothExt<T> for (Vec<T>, Vec<T>) {
    fn apply_both<U, F: Fn(Vec<T>) -> U>(self, f: F) -> (U, U) {
        (f(self.0), f(self.1))
    }
}