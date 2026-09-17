//! `kanon_supp_demo_syn` — Detailed walkthrough harness for the
//! supplementary material's synthetic-data example, **P2.3-syn**.
//!
//! P2.3-syn is *modeled on* P2.3 (same BB_Q6 binding box, same two-QID,
//! k/l/t-anonymity structure) but is not P2.3: P2.3 itself is already
//! fixed in the paper's Table 2, with `EventOrigin`/`Action` evaluated on
//! the real BPIC 2017 log. On the small synthetic OCED used for testing,
//! those two attributes turned out to be constant across every binding
//! (see `kanon_supp_demo.rs`'s output), collapsing everything into one
//! trivially-anonymous class — not useful as a worked example. Inspecting
//! the synthetic OCED's real attribute values (`kanon_inspect.rs`) showed
//! that `ApplicationType` and `LoanGoal`, both read directly off
//! `O_Created`, do produce a genuine, hand-checkable partition there, so
//! P2.3-syn reads those two instead:
//!
//!   - q1: self-QID on `O_Created`, reads `ApplicationType`.
//!   - q2: self-QID on `O_Created`, reads `LoanGoal`.
//!   - sensitive attribute: `OfferedAmount`.
//!
//! Both QIDs share BB_Q6's pattern (Offer, O_Created) and match into
//! (OV0, EV0); unlike P2.3, q2 does not read from O_Accepted at all. This
//! is deliberate: P2.3-syn's job is to illustrate the pipeline end to end
//! on data small enough to check by hand, not to reproduce P2.3's exact
//! pattern shapes.
//!
//! Prints the same five artifacts as `kanon_supp_demo.rs`:
//!
//!   1. The BB_Q6 output size.
//!   2. The number of matchings found for each QID (`find_matchings`).
//!   3. For every protected `O_Created` event: its source set `Src_q(o)`
//!      for each QID (`compute_source_set`) and the corresponding marginal
//!      fingerprint.
//!   4. The full fingerprint-to-equivalence-class partition
//!      (`compute_fingerprints`).
//!   5. The final `AnonReport` (`check_policy`): per-class k/l/t results,
//!      sensitive values, and any elements/values at risk.
//!
//! ## Uso
//!
//! Coloca este archivo junto a `main.rs` en el crate `kanon-demo` (por
//! ejemplo como un binario adicional) y ejecútalo con:
//!
//! ```text
//! cargo run --release -p kanon-demo --bin kanon_supp_demo_syn -- ./bpic2017-ocel2-synth.json
//! ```

use std::collections::HashMap;
use std::sync::Arc;

use process_mining::core::event_data::object_centric::linked_ocel::{
    slim_linked_ocel::EventOrObjectIndex, LinkedOCELAccess, SlimLinkedOCEL,
};
use process_mining::Importable;

use ocpq_shared::binding_box::structs::{
    Binding, BindingBox, BindingBoxTree, BindingBoxTreeNode, EventVariable, Filter, ObjectVariable,
};
use ocpq_shared::kanon::{
    check_policy, compute_fingerprints, find_matchings,
    fingerprint::{compute_source_set, source_set_to_marginal},
    policy::{AnonPolicy, Pattern, ProtectedVar, QidAttribute, QuasiIdentifier, SourceVar},
};

// =============================================================================
// Índices de variables (BB_Q6)
// =============================================================================

const OV0: ObjectVariable = ObjectVariable(0); // Offer
const EV0: EventVariable = EventVariable(0); // O_Created
const EV1: EventVariable = EventVariable(1); // O_Accepted (declarado en BB_Q6, no leído por ningún QID aquí)

// =============================================================================
// main
// =============================================================================

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let path = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| "./bpic2017-ocel2-synth.json".to_string());

    println!("Cargando OCEL desde: {path}");
    let ocel = SlimLinkedOCEL::import_from_path(&path).expect("Error al cargar el OCEL");
    println!(
        "OCEL cargado: {} eventos, {} objetos\n",
        ocel.get_num_evs(),
        ocel.get_num_obs(),
    );

    // ── BB_Q6 y su evaluación ───────────────────────────────────────────────
    let bbox = build_bb_q6();
    let out = evaluate(&bbox, &ocel);
    println!("BB_Q6: {} bindings\n", out.len());

    // ── Política P2.3-syn ────────────────────────────────────────────────────
    let policy = p2_3_syn_policy();

    println!("── Matchings ────────────────────────────────────────────────");
    for (i, qid) in policy.qids.iter().enumerate() {
        let matchings = find_matchings(&qid.pattern, &bbox);
        println!(
            "  q{} ({}): {} matching(s) into BB_Q6",
            i + 1,
            qid.id,
            matchings.len()
        );
    }

    // ── Elementos protegidos: todos los O_Created ──────────────────────────
    let protected: Vec<EventOrObjectIndex> = ocel
        .get_evs_of_type("O_Created")
        .map(|idx| EventOrObjectIndex::Event(*idx))
        .collect();
    println!("\nElementos protegidos (O_Created): {}\n", protected.len());

    println!("── Source sets y fingerprints marginales por elemento ────────");
    for elem in &protected {
        let raw_id = match elem {
            EventOrObjectIndex::Event(idx) => ocel.get_ev_id(idx),
            EventOrObjectIndex::Object(idx) => ocel.get_ob_id(idx),
        };
        println!("  O_Created:{raw_id}");
        for (i, qid) in policy.qids.iter().enumerate() {
            let src = compute_source_set(qid, *elem, &bbox, &out, &ocel);
            let mut src_sorted: Vec<_> = src.iter().cloned().collect();
            src_sorted.sort();
            let marginal = source_set_to_marginal(&src);
            println!("    Src_q{}: {:?}", i + 1, src_sorted);
            println!("    fp_q{}:  {:?}", i + 1, marginal);
        }
    }

    // ── Fingerprints completos y clases de equivalencia ────────────────────
    println!("\n── Clases de equivalencia (fingerprint → miembros) ───────────");
    let classes = compute_fingerprints(&policy, &bbox, &out, &ocel);
    for (fp, members) in &classes {
        println!("  fp={fp:?}\n    → {members:?}");
    }

    // ── AnonReport completo ─────────────────────────────────────────────────
    println!("\n── AnonReport (check_policy) ──────────────────────────────────");
    let report = check_policy(&policy, &bbox, &out, &ocel);
    println!("  {}", report.summary());
    println!(
        "  QIDs activados: {:?} | no activados: {:?}",
        report.activated_qid_ids, report.non_activated_qid_ids
    );
    for class in &report.equiv_classes {
        println!(
            "  clase fp={:?}\n    members={:?}\n    sensitive={:?}\n    k_ok={} l_ok={} t_ok={} emd={:?}",
            class.fingerprint,
            class.members,
            class.sensitive_values,
            class.k_ok,
            class.l_ok,
            class.t_ok,
            class.emd
        );
    }
    if !report.elements_violating_k.is_empty() {
        println!(
            "\n  Elementos en riesgo k: {:?}",
            report.elements_violating_k
        );
    }
    for r in &report.sensitive_values_at_risk {
        if !r.at_risk_values.is_empty() {
            println!("  Valores en riesgo [{}]: {:?}", r.attr_name, r.at_risk_values);
        }
    }
}

// =============================================================================
// Evaluación del binding box (sin medición de tiempos, no la necesitamos aquí)
// =============================================================================

fn evaluate(bbox: &BindingBox, ocel: &SlimLinkedOCEL) -> Vec<Arc<Binding>> {
    let tree = BindingBoxTree {
        nodes: vec![BindingBoxTreeNode::Box(bbox.clone(), vec![])],
        edge_names: HashMap::new(),
    };
    let (results, skipped) = tree
        .evaluate(ocel)
        .unwrap_or_else(|e| panic!("Error evaluando BB_Q6: {e}"));
    if skipped {
        eprintln!("  Advertencia: algunos bindings de BB_Q6 omitidos");
    }
    results.into_iter().map(|(_i, b, _v)| b).collect()
}

// =============================================================================
// BB_Q6 y helpers de construcción (idénticos a los de kanon_demo/main.rs)
// =============================================================================

fn empty_bbox() -> BindingBox {
    BindingBox {
        new_event_vars: HashMap::new(),
        new_object_vars: HashMap::new(),
        filters: vec![],
        size_filters: vec![],
        constraints: vec![],
        ev_var_labels: HashMap::new(),
        ob_var_labels: HashMap::new(),
        labels: vec![],
    }
}

/// BB_Q6 — Offer (OV0) con su O_Created (EV0) y su O_Accepted (EV1).
/// (EV1 se declara para mantener BB_Q6 idéntico al usado por P2.3 y el
/// resto de `kanon_demo`; ningún QID de P2.3-syn lo lee.)
fn build_bb_q6() -> BindingBox {
    BindingBox {
        new_object_vars: [(OV0, ["Offer".to_string()].into())].into(),
        new_event_vars: [
            (EV0, ["O_Created".to_string()].into()),
            (EV1, ["O_Accepted".to_string()].into()),
        ]
        .into(),
        filters: vec![
            Filter::O2E { object: OV0, event: EV0, qualifier: None, filter_label: None },
            Filter::O2E { object: OV0, event: EV1, qualifier: None, filter_label: None },
        ],
        ..empty_bbox()
    }
}

fn make_bbox(
    ob_vars: Vec<(ObjectVariable, &str)>,
    ev_vars: Vec<(EventVariable, &str)>,
    filters: Vec<Filter>,
) -> BindingBox {
    BindingBox {
        new_object_vars: ob_vars.into_iter().map(|(v, t)| (v, [t.to_string()].into())).collect(),
        new_event_vars: ev_vars.into_iter().map(|(v, t)| (v, [t.to_string()].into())).collect(),
        filters,
        ..empty_bbox()
    }
}

fn pat(
    ob_vars: Vec<(ObjectVariable, &str)>,
    ev_vars: Vec<(EventVariable, &str)>,
    filters: Vec<Filter>,
) -> Pattern {
    Pattern::try_from_box(&make_bbox(ob_vars, ev_vars, filters)).unwrap()
}

fn o2e(ob: ObjectVariable, ev: EventVariable) -> Filter {
    Filter::O2E { object: ob, event: ev, qualifier: None, filter_label: None }
}

// =============================================================================
// P2.3-syn — la política del material suplementario (variante sintética)
// =============================================================================

/// P2.3-syn — Dos QIDs autorreferentes sobre O_Created, ambos con el mismo
/// patrón (Offer, O_Created) → (OV0, EV0):
///
/// q1 lee `ApplicationType`; q2 lee `LoanGoal`. `OfferedAmount` como
/// sensible. Con k=2, l=2, ambas clases singleton de la partición real
/// (oc3, oc5) violan k- y l-anonimidad; t=0.9 se incluye por completitud
/// aunque no es el foco del ejemplo.
fn p2_3_syn_policy() -> AnonPolicy {
    let pat_self = pat(
        vec![(OV0, "Offer")],
        vec![(EV0, "O_Created")],
        vec![o2e(OV0, EV0)],
    );
    let q1 = QuasiIdentifier {
        id: "q1_ocreated_apptype".to_string(),
        pattern: pat_self.clone(),
        protected_var: ProtectedVar::Event(EV0),
        source_var: SourceVar::Event(EV0),
        attribute: QidAttribute::Named("ApplicationType".to_string()),
    };
    let q2 = QuasiIdentifier {
        id: "q2_ocreated_loangoal".to_string(),
        pattern: pat_self,
        protected_var: ProtectedVar::Event(EV0),
        source_var: SourceVar::Event(EV0),
        attribute: QidAttribute::Named("LoanGoal".to_string()),
    };
    AnonPolicy {
        qids: vec![q1, q2],
        sensitive_attrs: vec!["OfferedAmount".to_string()],
        k: 2,
        l: 2,
        t: 0.9,
    }
}
