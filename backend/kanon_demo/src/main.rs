//! # `kanon_demo` — timing harness for the k-anonymity framework
//!
//! Runs nine experiments (3 binding boxes × 3 policies) over the BPI
//! Challenge 2017 OCEL, timing each pipeline phase.
//!
//! ## Design: events as the protected type
//!
//! BPI 2017 objects (Application, Offer, Case_R, Workflow) carry no
//! attributes of their own; rich attributes (LoanGoal, ApplicationType,
//! EventOrigin, ...) live on **events**. All policies therefore protect an
//! event, not an object; the object stays in the binding box for structural
//! context but is not the element being anonymised.
//!
//! ## Phases timed per experiment
//!
//! 1. Activation (`find_matchings` × QID)
//! 2. `build_context` (active binding sets + source sets + fingerprints)
//! 3. `eval_k`, `eval_l`, `eval_t`
//! 4. `find_k_max`, `find_l_max`, `find_t_min`
//! 5. `elements_at_risk` + `sensitive_values_at_risk`
//!
//! ## Usage
//!
//! ```text
//! cargo run --release -p kanon-demo -- <path/to/bpic2017.json>
//! ```

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use process_mining::core::event_data::object_centric::linked_ocel::{
    LinkedOCELAccess, SlimLinkedOCEL,
};
use process_mining::Importable;

use ocpq_shared::binding_box::structs::{
    Binding, BindingBox, BindingBoxTree, BindingBoxTreeNode, EventVariable, Filter,
    ObjectVariable,
};
use ocpq_shared::kanon::{
    build_context, elements_at_risk, eval_k, eval_l, eval_t, find_k_max, find_l_max, find_t_min,
    sensitive_values_at_risk,
    policy::{AnonPolicy, Pattern, ProtectedVar, QidAttribute, QuasiIdentifier, SourceVar},
};

// =============================================================================
// Variable indices
// =============================================================================

const OV0: ObjectVariable = ObjectVariable(0); // Application / Offer
const OV1: ObjectVariable = ObjectVariable(1); // Offer_1 (BB_Q7) / Case_R (pattern)
const OV2: ObjectVariable = ObjectVariable(2); // Offer_2 (BB_Q7)

const EV0: EventVariable = EventVariable(0); // A_Submitted / O_Created / A_Validating
const EV1: EventVariable = EventVariable(1); // O_Accepted / O_Created_1 (BB_Q7)
const EV2: EventVariable = EventVariable(2); // O_Created_2 (BB_Q7)

// =============================================================================
// Timing log
// =============================================================================

struct Timings(Vec<(&'static str, Duration, String)>);

impl Timings {
    fn new() -> Self { Self(Vec::new()) }

    fn record(&mut self, phase: &'static str, d: Duration, note: impl Into<String>) {
        self.0.push((phase, d, note.into()));
    }

    fn print(&self, header: &str) {
        println!("  ┌─ {header}");
        for (phase, d, note) in &self.0 {
            println!("  │  {:52} {:>10.3} ms  {}", phase, d.as_secs_f64() * 1000.0, note);
        }
        let total: f64 = self.0.iter().map(|(_, d, _)| d.as_secs_f64() * 1000.0).sum();
        println!("  └─ total: {total:.3} ms");
    }
}

// =============================================================================
// main
// =============================================================================

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let path = args.get(1).cloned().unwrap_or_else(|| {
        eprintln!("Usage: kanon_demo <path/to/bpic2017.json>");
        std::process::exit(1);
    });

    println!("Loading OCEL from: {path}");
    let t0 = Instant::now();
    let ocel = SlimLinkedOCEL::import_from_path(&path).expect("Failed to load OCEL");
    println!(
        "OCEL loaded in {:.1} ms: {} events, {} objects\n",
        t0.elapsed().as_secs_f64() * 1000.0,
        ocel.get_num_evs(),
        ocel.get_num_obs(),
    );

    let bb_q1 = build_bb_q1();
    let bb_q6 = build_bb_q6();
    let bb_q7 = build_bb_q7();

    println!("Evaluating binding boxes with the OCPQ engine...");
    let (out_q1, t_q1) = timed_evaluate(&bb_q1, &ocel, "BB_Q1");
    let (out_q6, t_q6) = timed_evaluate(&bb_q6, &ocel, "BB_Q6");
    let (out_q7, t_q7) = timed_evaluate(&bb_q7, &ocel, "BB_Q7");
    println!("  BB_Q1: {} bindings in {:.1} ms", out_q1.len(), t_q1.as_secs_f64() * 1000.0);
    println!("  BB_Q6: {} bindings in {:.1} ms", out_q6.len(), t_q6.as_secs_f64() * 1000.0);
    println!("  BB_Q7: {} bindings in {:.1} ms\n", out_q7.len(), t_q7.as_secs_f64() * 1000.0);

    type PolicyFn = fn() -> AnonPolicy;
    let experiments: &[(&str, &BindingBox, &[Arc<Binding>], PolicyFn)] = &[
        ("P1.1 — BB_Q1 · Not activated · Types entirely absent",
            &bb_q1, &out_q1, p1_1_policy),
        ("P1.2 — BB_Q1 · Activated · One QID, one matching · Protects A_Submitted",
            &bb_q1, &out_q1, p1_2_policy),
        ("P1.3 — BB_Q1 · Partial activation · q1 activated, q2 not · Protects A_Submitted",
            &bb_q1, &out_q1, p1_3_policy),
        ("P2.1 — BB_Q6 · Not activated · Entirely different domain",
            &bb_q6, &out_q6, p2_1_policy),
        ("P2.2 — BB_Q6 · Activated · Pattern ⊂ bbox · Protects O_Created",
            &bb_q6, &out_q6, p2_2_policy),
        ("P2.3 — BB_Q6 · Activated · Two QIDs, independent matchings · Protects O_Created",
            &bb_q6, &out_q6, p2_3_policy),
        ("P3.1 — BB_Q7 · Not activated · Object matches, event does not",
            &bb_q7, &out_q7, p3_1_policy),
        ("P3.2 — BB_Q7 · Activated · One QID, two matchings · Protects O_Created",
            &bb_q7, &out_q7, p3_2_policy),
        ("P3.3 — BB_Q7 · Activated · Two QIDs, two matchings each · Protects O_Created",
            &bb_q7, &out_q7, p3_3_policy),
    ];

    println!("══════════════════════════════════════════════════════════════════");
    for (label, bbox, out, policy_fn) in experiments {
        println!("\n▶ {label}");
        run_experiment(bbox, out, policy_fn(), &ocel);
        println!("══════════════════════════════════════════════════════════════════");
    }
}

// =============================================================================
// Per-experiment execution, timed by phase
// =============================================================================

fn run_experiment(
    bbox: &BindingBox,
    out: &[Arc<Binding>],
    policy: AnonPolicy,
    ocel: &SlimLinkedOCEL,
) {
    let mut t = Timings::new();

    // Phase 1: activation
    let t1 = Instant::now();
    let n_activated = policy.qids.iter()
        .filter(|qid| {
            use ocpq_shared::kanon::find_matchings;
            !find_matchings(&qid.pattern, bbox).is_empty()
        })
        .count();
    t.record("Activation (find_matchings × QID)", t1.elapsed(),
        format!("{}/{} QIDs activated", n_activated, policy.qids.len()));

    // Phase 2: build_context
    let t2 = Instant::now();
    let ctx = build_context(&policy, bbox, out, ocel);
    let n_classes  = ctx.class_map.len();
    let n_elements: usize = ctx.class_map.values().map(|v| v.len()).sum();
    t.record("build_context (active BS + source sets + fingerprints)", t2.elapsed(),
        format!("{n_elements} elements → {n_classes} classes"));

    if !ctx.policy_activated() {
        t.print("→ Policy not activated");
        println!("  (metrics not evaluated)");
        return;
    }

    // Phase 3: eval_k / eval_l / eval_t
    let t3 = Instant::now();
    let k_result = eval_k(&ctx, policy.k);
    t.record("eval_k", t3.elapsed(),
        format!("k={} → {}", policy.k, if k_result.satisfied { "✓" } else { "✗" }));

    let t4 = Instant::now();
    let l_result = eval_l(&ctx, policy.l);
    t.record("eval_l", t4.elapsed(),
        format!("l={} → {}", policy.l, if l_result.satisfied { "✓" } else { "✗" }));

    let t5 = Instant::now();
    let t_result = eval_t(&ctx, policy.t);
    t.record("eval_t", t5.elapsed(),
        format!("t={} → {}", policy.t, if t_result.satisfied { "✓" } else { "✗" }));

    // Phase 4: limit metrics
    let t6 = Instant::now();
    let k_max = find_k_max(&ctx);
    let l_max = find_l_max(&ctx);
    let t_min = find_t_min(&ctx, &t_result);
    t.record("find_k/l/t max/min", t6.elapsed(),
        format!("k_max={k_max} l_max={l_max} t_min={t_min:?}"));

    // Phase 5: risk analysis
    let t7 = Instant::now();
    let at_risk   = elements_at_risk(&k_result);
    let sens_risk = sensitive_values_at_risk(&l_result, &t_result, &policy.sensitive_attrs);
    t.record("elements_at_risk + sensitive_values_at_risk", t7.elapsed(),
        format!("{} elements at k-risk, {} attrs with at-risk values",
            at_risk.len(),
            sens_risk.iter().filter(|r| !r.at_risk_values.is_empty()).count()));

    t.print("Phases");
    println!("  Summary:");
    println!("    Protected elements:     {n_elements}");
    println!("    Equivalence classes:    {n_classes}");
    println!("    k={} {} | l={} {} | t={} {}",
        policy.k, if k_result.satisfied { "✓" } else { "✗" },
        policy.l, if l_result.satisfied { "✓" } else { "✗" },
        policy.t, if t_result.satisfied { "✓" } else { "✗" });
    println!("    k_max={k_max} | l_max={l_max} | t_min={t_min:?}");
    if !at_risk.is_empty() {
        println!("    Elements at k-risk: {} (first 5: {:?})",
            at_risk.len(), at_risk.iter().take(5).collect::<Vec<_>>());
    }
    for r in &sens_risk {
        if !r.at_risk_values.is_empty() {
            println!("    At-risk values [{}]: {:?}", r.attr_name,
                r.at_risk_values.iter().take(10).collect::<Vec<_>>());
        }
    }
}

// =============================================================================
// Binding box evaluation
// =============================================================================

fn timed_evaluate(bbox: &BindingBox, ocel: &SlimLinkedOCEL, label: &str)
    -> (Vec<Arc<Binding>>, Duration)
{
    let tree = BindingBoxTree {
        nodes:      vec![BindingBoxTreeNode::Box(bbox.clone(), vec![])],
        edge_names: HashMap::new(),
    };
    let t = Instant::now();
    let (results, skipped) = tree.evaluate(ocel)
        .unwrap_or_else(|e| panic!("Error evaluating {label}: {e}"));
    let elapsed = t.elapsed();
    if skipped { eprintln!("  Warning: some bindings of {label} were skipped"); }
    (results.into_iter().map(|(_i, b, _v)| b).collect(), elapsed)
}

// =============================================================================
// Binding boxes
// =============================================================================

fn empty_bbox() -> BindingBox {
    BindingBox {
        new_event_vars:  HashMap::new(),
        new_object_vars: HashMap::new(),
        filters:         vec![],
        size_filters:    vec![],
        constraints:     vec![],
        ev_var_labels:   HashMap::new(),
        ob_var_labels:   HashMap::new(),
        labels:          vec![],
    }
}

/// BB_Q1 — Application (OV0) with its A_Submitted event (EV0).
///
/// `O2E(EV0, OV0, *)`. A_Submitted carries the rich attributes
/// (ApplicationType, LoanGoal, CreditScore, ...): the natural protected type
/// for Q1 policies.
fn build_bb_q1() -> BindingBox {
    BindingBox {
        new_object_vars: [(OV0, ["Application".to_string()].into())].into(),
        new_event_vars:  [(EV0, ["A_Submitted".to_string()].into())].into(),
        filters: vec![Filter::O2E {
            object: OV0, event: EV0, qualifier: None, filter_label: None,
        }],
        ..empty_bbox()
    }
}

/// BB_Q6 — Offer (OV0) with O_Created (EV0) and O_Accepted (EV1).
///
/// Both events carry rich attributes; O_Created is the natural protected
/// type (more events than O_Accepted, since some Offers are never accepted).
fn build_bb_q6() -> BindingBox {
    BindingBox {
        new_object_vars: [(OV0, ["Offer".to_string()].into())].into(),
        new_event_vars: [
            (EV0, ["O_Created".to_string()].into()),
            (EV1, ["O_Accepted".to_string()].into()),
        ].into(),
        filters: vec![
            Filter::O2E { object: OV0, event: EV0, qualifier: None, filter_label: None },
            Filter::O2E { object: OV0, event: EV1, qualifier: None, filter_label: None },
        ],
        ..empty_bbox()
    }
}

/// BB_Q7 — Application (OV0), two Offers (OV1, OV2) and their O_Created
/// events (EV1, EV2).
///
/// EV1/EV2 is the O_Created of Offer_1/Offer_2; Q7 policies protect EV1.
fn build_bb_q7() -> BindingBox {
    BindingBox {
        new_object_vars: [
            (OV0, ["Application".to_string()].into()),
            (OV1, ["Offer".to_string()].into()),
            (OV2, ["Offer".to_string()].into()),
        ].into(),
        new_event_vars: [
            (EV1, ["O_Created".to_string()].into()),
            (EV2, ["O_Created".to_string()].into()),
        ].into(),
        filters: vec![
            Filter::O2O { object: OV0, other_object: OV1, qualifier: None, filter_label: None },
            Filter::O2O { object: OV0, other_object: OV2, qualifier: None, filter_label: None },
            Filter::O2E { object: OV1, event: EV1, qualifier: None, filter_label: None },
            Filter::O2E { object: OV2, event: EV2, qualifier: None, filter_label: None },
        ],
        ..empty_bbox()
    }
}

// =============================================================================
// Pattern-construction helpers
// =============================================================================

fn make_bbox(ob_vars: Vec<(ObjectVariable, &str)>,
             ev_vars: Vec<(EventVariable, &str)>,
             filters: Vec<Filter>) -> BindingBox {
    BindingBox {
        new_object_vars: ob_vars.into_iter()
            .map(|(v, t)| (v, [t.to_string()].into())).collect(),
        new_event_vars: ev_vars.into_iter()
            .map(|(v, t)| (v, [t.to_string()].into())).collect(),
        filters,
        ..empty_bbox()
    }
}

fn pat(ob_vars: Vec<(ObjectVariable, &str)>,
       ev_vars: Vec<(EventVariable, &str)>,
       filters: Vec<Filter>) -> Pattern {
    Pattern::try_from_box(&make_bbox(ob_vars, ev_vars, filters)).unwrap()
}

fn o2e(ob: ObjectVariable, ev: EventVariable) -> Filter {
    Filter::O2E { object: ob, event: ev, qualifier: None, filter_label: None }
}
fn o2o(ob: ObjectVariable, other: ObjectVariable) -> Filter {
    Filter::O2O { object: ob, other_object: other, qualifier: None, filter_label: None }
}

// =============================================================================
// The nine policies
// =============================================================================

// ── BB_Q1 ────────────────────────────────────────────────────────────────────

/// P1.1 — Not activated.
///
/// Both QIDs use a `Workflow` + `A_Validating` pattern, types entirely
/// absent from BB_Q1 → `find_matchings` empty for both → policy not activated.
fn p1_1_policy() -> AnonPolicy {
    // Phantom pattern: Workflow + A_Validating, neither present in BB_Q1.
    let pat_phantom = pat(
        vec![(OV1, "Workflow")],
        vec![(EV0, "A_Validating")],
        vec![o2e(OV1, EV0)],
    );
    let q1 = QuasiIdentifier {
        id:            "q1_phantom_apptype".to_string(),
        pattern:       pat_phantom.clone(),
        protected_var: ProtectedVar::Event(EV0),   // A_Validating — absent
        source_var:    SourceVar::Event(EV0),
        attribute:     QidAttribute::Named("ApplicationType".to_string()),
    };
    let q2 = QuasiIdentifier {
        id:            "q2_phantom_loangeal".to_string(),
        pattern:       pat_phantom,
        protected_var: ProtectedVar::Event(EV0),
        source_var:    SourceVar::Event(EV0),
        attribute:     QidAttribute::Named("LoanGoal".to_string()),
    };
    AnonPolicy { qids: vec![q1, q2], sensitive_attrs: vec!["EventOrigin".to_string()],
        k: 2, l: 2, t: 0.9 }
}

/// P1.2 — One QID, one matching.
///
/// Pattern = BB_Q1 exactly. `A_Submitted` (EV0) is the protected type; the
/// QID reads `ApplicationType` from the protected event itself
/// (source_var = protected_var). Two possible values (New credit / Limit
/// raise) → exactly 2 large equivalence classes. `LoanGoal` (14 values) as
/// sensitive → high l_max.
fn p1_2_policy() -> AnonPolicy {
    let pat_q1 = pat(
        vec![(OV0, "Application")],
        vec![(EV0, "A_Submitted")],
        vec![o2e(OV0, EV0)],
    );
    let q1 = QuasiIdentifier {
        id:            "q1_asubmitted_apptype".to_string(),
        pattern:       pat_q1,
        protected_var: ProtectedVar::Event(EV0),   // A_Submitted
        source_var:    SourceVar::Event(EV0),       // self-QID
        attribute:     QidAttribute::Named("ApplicationType".to_string()),
    };
    AnonPolicy { qids: vec![q1], sensitive_attrs: vec!["LoanGoal".to_string()],
        k: 2, l: 2, t: 0.9 }
}

/// P1.3 — Partial activation.
///
/// q1: pattern = BB_Q1, activated with one matching; reads `LoanGoal` of the
///     protected A_Submitted (14 values → more classes than P1.2).
/// q2: pattern requires a `Case_R` linked to the same A_Submitted — absent
///     from BB_Q1 → not activated → contributes an empty marginal.
/// `ApplicationType` (2 values) as sensitive: easy to interpret.
fn p1_3_policy() -> AnonPolicy {
    let pat_q1 = pat(
        vec![(OV0, "Application")],
        vec![(EV0, "A_Submitted")],
        vec![o2e(OV0, EV0)],
    );
    // Pattern with Case_R — absent from BB_Q1 → not activated.
    let pat_q2 = pat(
        vec![(OV0, "Application"), (OV1, "Case_R")],
        vec![(EV0, "A_Submitted")],
        vec![o2e(OV0, EV0), o2e(OV1, EV0)],
    );
    let q1 = QuasiIdentifier {
        id:            "q1_asubmitted_loangeal".to_string(),
        pattern:       pat_q1,
        protected_var: ProtectedVar::Event(EV0),
        source_var:    SourceVar::Event(EV0),
        attribute:     QidAttribute::Named("LoanGoal".to_string()),
    };
    let q2 = QuasiIdentifier {
        id:            "q2_case_r_id_notactivated".to_string(),
        pattern:       pat_q2,
        protected_var: ProtectedVar::Event(EV0),   // A_Submitted (same)
        source_var:    SourceVar::Object(OV1),      // Case_R — absent
        attribute:     QidAttribute::Id,
    };
    AnonPolicy { qids: vec![q1, q2], sensitive_attrs: vec!["ApplicationType".to_string()],
        k: 2, l: 2, t: 0.9 }
}

// ── BB_Q6 ────────────────────────────────────────────────────────────────────

/// P2.1 — Not activated.
///
/// Pattern targets `Application` + `A_Submitted`; BB_Q6 has `Offer`,
/// `O_Created`, `O_Accepted` — no type matches → not activated. Contrast
/// with P1.2: same pattern, different bbox.
fn p2_1_policy() -> AnonPolicy {
    let pat_q1 = pat(
        vec![(OV0, "Application")],
        vec![(EV0, "A_Submitted")],
        vec![o2e(OV0, EV0)],
    );
    let q1 = QuasiIdentifier {
        id:            "q1_asubmitted_in_q6".to_string(),
        pattern:       pat_q1,
        protected_var: ProtectedVar::Event(EV0),
        source_var:    SourceVar::Event(EV0),
        attribute:     QidAttribute::Named("ApplicationType".to_string()),
    };
    AnonPolicy { qids: vec![q1], sensitive_attrs: vec!["LoanGoal".to_string()],
        k: 2, l: 2, t: 0.9 }
}

/// P2.2 — Activated, pattern strictly contained in bbox.
///
/// Pattern uses only `(Offer, O_Created)`; BB_Q6 also has `O_Accepted` (EV1),
/// an extra variable ignored by the matching. `O_Created` (EV0) is the
/// protected type. `EventOrigin` of O_Created: 3 values
/// (Application/Workflow/Offer). `ApplicationType` as sensitive: 2 values →
/// l easily satisfied.
fn p2_2_policy() -> AnonPolicy {
    let pat_q1 = pat(
        vec![(OV0, "Offer")],
        vec![(EV0, "O_Created")],
        vec![o2e(OV0, EV0)],
    );
    let q1 = QuasiIdentifier {
        id:            "q1_ocreated_eventorigin".to_string(),
        pattern:       pat_q1,
        protected_var: ProtectedVar::Event(EV0),   // O_Created
        source_var:    SourceVar::Event(EV0),       // self-QID
        attribute:     QidAttribute::Named("EventOrigin".to_string()),
    };
    AnonPolicy { qids: vec![q1], sensitive_attrs: vec!["ApplicationType".to_string()],
        k: 2, l: 2, t: 0.9 }
}

/// P2.3 — Two QIDs, independent matchings.
///
/// q1: pattern (Offer, O_Created) → matches (OV0, EV0); reads EventOrigin.
/// q2: pattern (Offer, O_Created, O_Accepted) → matches (OV0, EV0, EV1);
///     reads Action from O_Accepted. Both protect the same event EV0
///     (O_Created); the fingerprint combines EventOrigin and Action.
/// `OfferedAmount` as sensitive (numeric, several values).
fn p2_3_policy() -> AnonPolicy {
    let pat_q1 = pat(
        vec![(OV0, "Offer")],
        vec![(EV0, "O_Created")],
        vec![o2e(OV0, EV0)],
    );
    // q2 uses O_Accepted as source; O_Created remains the protected event.
    let pat_q2 = pat(
        vec![(OV0, "Offer")],
        vec![(EV0, "O_Created"), (EV1, "O_Accepted")],
        vec![o2e(OV0, EV0), o2e(OV0, EV1)],
    );
    let q1 = QuasiIdentifier {
        id:            "q1_ocreated_origin".to_string(),
        pattern:       pat_q1,
        protected_var: ProtectedVar::Event(EV0),
        source_var:    SourceVar::Event(EV0),
        attribute:     QidAttribute::Named("EventOrigin".to_string()),
    };
    let q2 = QuasiIdentifier {
        id:            "q2_oaccepted_action".to_string(),
        pattern:       pat_q2,
        protected_var: ProtectedVar::Event(EV0),   // O_Created (same protected)
        source_var:    SourceVar::Event(EV1),       // O_Accepted as source
        attribute:     QidAttribute::Named("Action".to_string()),
    };
    AnonPolicy { qids: vec![q1, q2], sensitive_attrs: vec!["OfferedAmount".to_string()],
        k: 2, l: 2, t: 0.9 }
}

// ── BB_Q7 ────────────────────────────────────────────────────────────────────

/// P3.1 — Not activated.
///
/// Pattern requires `O_Accepted` as the protected event; BB_Q7 only has
/// `O_Created` (EV1, EV2) → incompatible event type → not activated. The
/// object type (Offer: OV1, OV2) does match, showing that a single
/// incompatible type suffices to block activation.
fn p3_1_policy() -> AnonPolicy {
    let pat_q1 = pat(
        vec![(OV0, "Offer")],
        vec![(EV1, "O_Accepted")],
        vec![o2e(OV0, EV1)],
    );
    let q1 = QuasiIdentifier {
        id:            "q1_oaccepted_amount_in_q7".to_string(),
        pattern:       pat_q1,
        protected_var: ProtectedVar::Event(EV1),   // O_Accepted — absent from BB_Q7
        source_var:    SourceVar::Event(EV1),
        attribute:     QidAttribute::Named("OfferedAmount".to_string()),
    };
    AnonPolicy { qids: vec![q1], sensitive_attrs: vec!["MonthlyCost".to_string()],
        k: 2, l: 2, t: 0.9 }
}

/// P3.2 — One QID, two matchings.
///
/// Pattern (Offer, O_Created) matches:
///   φ1: (OV1:{Offer}, EV1:{O_Created})
///   φ2: (OV2:{Offer}, EV2:{O_Created})
/// The protected type is EV1/EV2 depending on the matching; each protected
/// O_Created accumulates its own EventOrigin as source set.
/// `ApplicationType` as sensitive (2 values → classes with l ≥ 2 possible).
fn p3_2_policy() -> AnonPolicy {
    // Pattern uses OV0/EV0; the matching redirects to OV1/EV1 or OV2/EV2.
    let pat_q1 = pat(
        vec![(OV0, "Offer")],
        vec![(EV0, "O_Created")],
        vec![o2e(OV0, EV0)],
    );
    let q1 = QuasiIdentifier {
        id:            "q1_ocreated_origin_q7".to_string(),
        pattern:       pat_q1,
        protected_var: ProtectedVar::Event(EV0),   // will match EV1 or EV2
        source_var:    SourceVar::Event(EV0),
        attribute:     QidAttribute::Named("EventOrigin".to_string()),
    };
    AnonPolicy { qids: vec![q1], sensitive_attrs: vec!["ApplicationType".to_string()],
        k: 2, l: 2, t: 0.9 }
}

/// P3.3 — Two QIDs, two matchings each.
///
/// q1: pattern (Offer, O_Created) — two matchings (φ1, φ2); protects
///     O_Created, reads `EventOrigin` from it.
/// q2: pattern (Application, Offer, O_Created) via O2O + O2E — two matchings;
///     protects the same O_Created, reads `Action` from it. The pattern
///     adds Application for richer context, but the QID attribute differs
///     from q1's. Each O_Created's fingerprint combines both QIDs.
/// `LoanGoal` as sensitive (14 values → more variety).
fn p3_3_policy() -> AnonPolicy {
    let pat_q1 = pat(
        vec![(OV0, "Offer")],
        vec![(EV0, "O_Created")],
        vec![o2e(OV0, EV0)],
    );
    // q2 adds Application to the pattern via O2O, without changing the
    // protected type.
    let pat_q2 = pat(
        vec![(OV0, "Application"), (OV1, "Offer")],
        vec![(EV0, "O_Created")],
        vec![o2o(OV0, OV1), o2e(OV1, EV0)],
    );
    let q1 = QuasiIdentifier {
        id:            "q1_ocreated_origin_q7b".to_string(),
        pattern:       pat_q1,
        protected_var: ProtectedVar::Event(EV0),
        source_var:    SourceVar::Event(EV0),
        attribute:     QidAttribute::Named("EventOrigin".to_string()),
    };
    let q2 = QuasiIdentifier {
        id:            "q2_app_offer_ocreated_origin".to_string(),
        pattern:       pat_q2,
        protected_var: ProtectedVar::Event(EV0),
        source_var:    SourceVar::Event(EV0),
        attribute:     QidAttribute::Named("Action".to_string()),
    };
    AnonPolicy { qids: vec![q1, q2], sensitive_attrs: vec!["LoanGoal".to_string()],
        k: 2, l: 2, t: 0.9 }
}