//! Output types for an anonymity-policy evaluation run.
//!
//! [`AnonReport`], returned by [`crate::kanon::check_policy`], summarises:
//! activated QIDs, the equivalence-class partition, global k/l/t
//! satisfaction, and per-class detail.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use process_mining::core::event_data::object_centric::linked_ocel::SlimLinkedOCEL;

use crate::binding_box::structs::{Binding, BindingBox};
use crate::kanon::{
    fingerprint::{Fingerprint, QidValue},
    policy::AnonPolicy,
    properties::{
        build_context, elements_at_risk, eval_k, eval_l, eval_t,
        find_k_max, find_l_max, find_t_min, sensitive_values_at_risk,
    },
};

// ---------------------------------------------------------------------------
// EquivClass
// ---------------------------------------------------------------------------

/// A set of protected elements sharing the same [`Fingerprint`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EquivClass {
    /// Shared fingerprint (one marginal fingerprint per QID, policy order).
    pub fingerprint: Fingerprint,

    /// Type-qualified OCEL IDs of the members, `"<type>:<raw_id>"`.
    pub members: Vec<String>,

    /// Sensitive-attribute tuple per member (same order as `members`; each
    /// inner `Vec` follows `policy.sensitive_attrs` order).
    pub sensitive_values: Vec<Vec<QidValue>>,

    /// `|members| ≥ k`.
    pub k_ok: bool,

    /// Distinct sensitive tuples `≥ l`.
    pub l_ok: bool,

    /// Discrete EMD to the global distribution `≤ t`.
    pub t_ok: bool,

    /// Discrete EMD for this class (`None` if no sensitive attributes).
    pub emd: Option<f64>,
}

// ---------------------------------------------------------------------------
// AnonReport
// ---------------------------------------------------------------------------

/// The full result of evaluating an [`crate::kanon::AnonPolicy`] against a
/// binding box output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonReport {
    /// `true` iff at least one QID was activated; a non-activated policy
    /// imposes no constraint.
    pub policy_activated: bool,

    /// IDs of the activated QIDs.
    pub activated_qid_ids: Vec<String>,

    /// IDs of the non-activated QIDs.
    pub non_activated_qid_ids: Vec<String>,

    /// Total protected elements found in the OCEL.
    pub total_protected_elements: usize,

    /// All equivalence classes, largest first.
    pub equiv_classes: Vec<EquivClass>,

    /// `true` iff every class satisfies k-anonymity.
    pub k_satisfied: bool,

    /// `true` iff every class satisfies l-diversity (trivial when `l = 0`).
    pub l_satisfied: bool,

    /// `true` iff every class satisfies t-closeness (trivial when `t = 1.0`).
    pub t_satisfied: bool,

    /// Classes violating at least one of k, l, t.
    pub violating_classes: Vec<EquivClass>,

    /// Policy `k` (convenience copy).
    pub k: usize,

    /// Policy `l` (convenience copy).
    pub l: usize,

    /// Policy `t` (convenience copy).
    pub t: f64,

    // ── Derived metrics ────────────────────────────────────────────────────

    /// Size of the smallest equivalence class: the data satisfies
    /// k-anonymity for every `k ≤ k_max`. Zero if no protected elements.
    pub k_max: usize,

    /// Minimum distinct sensitive-tuple count across classes: the data
    /// satisfies l-diversity for every `l ≤ l_max`. Zero if no classes or
    /// no sensitive attributes.
    pub l_max: usize,

    /// Minimum discrete EMD across classes (best-case t-closeness): the data
    /// satisfies t-closeness for every `t ≥ t_min`. `None` if no sensitive
    /// attributes or no classes.
    pub t_min: Option<f64>,

    /// Type-qualified IDs in a class with fewer than `k` members.
    pub elements_violating_k: Vec<String>,

    /// Per sensitive attribute, distinct values appearing in classes
    /// violating l-diversity or t-closeness ("at risk").
    pub sensitive_values_at_risk: Vec<SensitiveAttrRisk>,
}

/// Values of one sensitive attribute at risk in some violating class.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensitiveAttrRisk {
    /// Attribute name.
    pub attr_name: String,
    /// Distinct at-risk values.
    pub at_risk_values: Vec<QidValue>,
}

// =============================================================================
// Public entry point
// =============================================================================

/// The framework's single public entry point: runs [`build_context`] and all
/// three evaluation layers, and assembles the [`AnonReport`].
///
/// # Panics (debug)
/// If `bbox` has constraints or labels (see `properties.rs`).
pub fn check_policy(
    policy: &AnonPolicy,
    bbox: &BindingBox,
    out: &[Arc<Binding>],
    ocel: &SlimLinkedOCEL,
) -> AnonReport {
    let ctx = build_context(policy, bbox, out, ocel);

    // Layer 1: pointwise
    let k_result = eval_k(&ctx, policy.k);
    let l_result = eval_l(&ctx, policy.l);
    let t_result = eval_t(&ctx, policy.t);

    // Layer 2: limits
    let k_max = find_k_max(&ctx);
    let l_max = find_l_max(&ctx);
    let t_min = find_t_min(&ctx, &t_result);

    // Layer 3: risk
    let elements_violating_k = elements_at_risk(&k_result);
    let sensitive_values_at_risk =
        sensitive_values_at_risk(&l_result, &t_result, &policy.sensitive_attrs);

    // Merge k/l/t per-class results by position: all layers produce classes
    // in the same order (sorted largest-first).
    let equiv_classes: Vec<EquivClass> = k_result
        .classes
        .iter()
        .zip(l_result.classes.iter())
        .zip(t_result.classes.iter())
        .map(|((kc, lc), tc)| EquivClass {
            // Recover the fingerprint from ctx via the (sorted) member set.
            fingerprint: ctx
                .class_map
                .iter()
                .find(|(_, v)| {
                    let mut a = (*v).clone(); a.sort();
                    let mut b = kc.members.clone(); b.sort();
                    a == b
                })
                .map(|(fp, _)| fp.clone())
                .unwrap_or_default(),
            members:          kc.members.clone(),
            sensitive_values: lc.sensitive_values.clone(),
            k_ok: kc.ok,
            l_ok: lc.ok,
            t_ok: tc.ok,
            emd:  tc.emd,
        })
        .collect();

    let violating_classes: Vec<EquivClass> = equiv_classes
        .iter()
        .filter(|c| !c.k_ok || !c.l_ok || !c.t_ok)
        .cloned()
        .collect();

    AnonReport {
        policy_activated:        ctx.policy_activated(),
        activated_qid_ids:       ctx.activated_qid_ids,
        non_activated_qid_ids:   ctx.non_activated_qid_ids,
        total_protected_elements: ctx.global_total,
        equiv_classes,
        k_satisfied: k_result.satisfied,
        l_satisfied: l_result.satisfied,
        t_satisfied: t_result.satisfied,
        violating_classes,
        k: policy.k,
        l: policy.l,
        t: policy.t,
        k_max,
        l_max,
        t_min,
        elements_violating_k,
        sensitive_values_at_risk,
    }
}

impl AnonReport {
    /// Returns a one-line human-readable summary of the evaluation result.
    pub fn summary(&self) -> String {
        format!(
            "Policy activated={}, elements={}, classes={}, \
             k({})={} [max={}], l({})={} [max={}], t({})={} [min={:?}]",
            self.policy_activated,
            self.total_protected_elements,
            self.equiv_classes.len(),
            self.k, self.k_satisfied, self.k_max,
            self.l, self.l_satisfied, self.l_max,
            self.t, self.t_satisfied, self.t_min,
        )
    }
}