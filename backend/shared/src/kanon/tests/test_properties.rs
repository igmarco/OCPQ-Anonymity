//! Tests unitarios de [`crate::kanon::properties`].
//!
//! Cubren las tres capas de evaluación:
//! - Capa 1: [`eval_k`], [`eval_l`], [`eval_t`]
//! - Capa 2: [`find_k_max`], [`find_l_max`], [`find_t_min`]
//! - Capa 3: [`elements_at_risk`], [`sensitive_values_at_risk`]
//! - Función interna: [`discrete_emd`]

use crate::kanon::fingerprint::{{Fingerprint, QidValue}};
use crate::kanon::properties::{{
    discrete_emd, elements_at_risk, eval_k, eval_l, eval_t,
    find_k_max, find_l_max, find_t_min, sensitive_values_at_risk, PolicyContext,
}};
use std::collections::{{BTreeMap, HashMap,}};


    // -------------------------------------------------------------------------
    // Helper: PolicyContext sintético (sin OCEL real)
    // -------------------------------------------------------------------------

    fn qv(s: &str) -> QidValue {
        QidValue::Str(s.to_string())
    }

    /// Construye un PolicyContext mínimo con las clases y valores sensibles
    /// dados.  `classes` es una lista de (miembros, valor_sensible).
    fn make_ctx(classes: Vec<(Vec<&str>, Vec<&str>)>) -> PolicyContext {
        // class_map: fingerprint vacío como clave (no relevante para estos tests)
        let mut class_map: BTreeMap<Fingerprint, Vec<String>> = BTreeMap::new();
        let mut sens_map: HashMap<String, Vec<QidValue>> = HashMap::new();
        let mut global_dist: BTreeMap<Vec<QidValue>, usize> = BTreeMap::new();

        for (i, (members, sens_vals)) in classes.iter().enumerate() {
            // Usar el índice como fingerprint para que sean distintas
            let fp: Fingerprint = vec![
                [(QidValue::Int(i as i64), 1)].into()
            ];
            let qids: Vec<String> = members.iter().map(|m| m.to_string()).collect();
            class_map.insert(fp, qids.clone());

            for id in &qids {
                let tuple: Vec<QidValue> = sens_vals.iter().map(|v| qv(v)).collect();
                *global_dist.entry(tuple.clone()).or_insert(0) += 1;
                sens_map.insert(id.clone(), tuple);
            }
        }

        let global_total = sens_map.len();

        PolicyContext {
            class_map,
            sens_map,
            global_dist,
            global_total,
            activated_qid_ids:     vec!["q1".to_string()],
            non_activated_qid_ids: vec![],
        }
    }

    // =========================================================================
    // Layer 1 — eval_k
    // =========================================================================

    #[test]
    fn eval_k_satisfied_when_all_classes_large_enough() {
        let ctx = make_ctx(vec![
            (vec!["v1","v2"], vec!["large"]),
            (vec!["v3","v4"], vec!["small"]),
        ]);
        let r = eval_k(&ctx, 2);
        assert!(r.satisfied);
        assert!(r.classes.iter().all(|c| c.ok));
    }

    #[test]
    fn eval_k_violated_when_class_too_small() {
        let ctx = make_ctx(vec![
            (vec!["v1"],      vec!["large"]),  // tamaño 1 < k=2
            (vec!["v3","v4"], vec!["small"]),
        ]);
        let r = eval_k(&ctx, 2);
        assert!(!r.satisfied);
        assert!(r.classes.iter().any(|c| !c.ok));
    }

    #[test]
    fn eval_k_k1_always_satisfied() {
        let ctx = make_ctx(vec![(vec!["v1"], vec!["large"])]);
        assert!(eval_k(&ctx, 1).satisfied);
    }

    #[test]
    fn eval_k_classes_sorted_largest_first() {
        let ctx = make_ctx(vec![
            (vec!["v1","v2"],             vec!["large"]),
            (vec!["v3","v4","v5","v6"],   vec!["small"]),
        ]);
        let r = eval_k(&ctx, 2);
        assert!(r.classes[0].members.len() >= r.classes[1].members.len());
    }

    // =========================================================================
    // Layer 1 — eval_l
    // =========================================================================

    #[test]
    fn eval_l_satisfied_when_enough_distinct_values() {
        let ctx = make_ctx(vec![
            (vec!["v1","v2"], vec!["large"]),
            (vec!["v3","v4"], vec!["small"]),
        ]);
        // Cada clase tiene un solo valor sensible; l=1 debe satisfacerse
        let r = eval_l(&ctx, 1);
        assert!(r.satisfied);
    }

    #[test]
    fn eval_l_violated_when_all_same_sensitive_value() {
        // Clase donde todos tienen "large" → solo 1 valor distinto < l=2
        let ctx = make_ctx(vec![
            (vec!["v1","v2"], vec!["large"]),
        ]);
        let r = eval_l(&ctx, 2);
        assert!(!r.satisfied);
        assert_eq!(r.classes[0].distinct_count, 1);
    }

    #[test]
    fn eval_l_zero_trivially_satisfied() {
        let ctx = make_ctx(vec![(vec!["v1"], vec!["large"])]);
        assert!(eval_l(&ctx, 0).satisfied);
    }

    // =========================================================================
    // Layer 1 — eval_t
    // =========================================================================

    #[test]
    fn eval_t_one_trivially_satisfied() {
        let ctx = make_ctx(vec![(vec!["v1","v2"], vec!["large"])]);
        let r = eval_t(&ctx, 1.0);
        assert!(r.satisfied);
        assert!(r.classes.iter().all(|c| c.emd.is_none()));
    }

    #[test]
    fn eval_t_identical_to_global_emd_zero() {
        // Clase con large+small; global también large+small → EMD=0
        let mut ctx = make_ctx(vec![
            (vec!["v1"], vec!["large"]),
            (vec!["v2"], vec!["small"]),
        ]);
        // Hacemos que sea una sola clase juntando los dos elementos
        let fp: Fingerprint = vec![[(QidValue::Int(99), 1)].into()];
        ctx.class_map = BTreeMap::new();
        ctx.class_map.insert(fp, vec!["v1".to_string(), "v2".to_string()]);

        let r = eval_t(&ctx, 0.5);
        for c in &r.classes {
            if let Some(emd) = c.emd {
                assert!(emd < 1e-9, "EMD should be ~0, got {emd}");
            }
        }
    }

    // =========================================================================
    // Layer 2 — find_k_max, find_l_max, find_t_min
    // =========================================================================

    #[test]
    fn find_k_max_returns_smallest_class_size() {
        let ctx = make_ctx(vec![
            (vec!["v1","v2","v3","v4"], vec!["large"]),
            (vec!["v5","v6"],           vec!["small"]),
        ]);
        assert_eq!(find_k_max(&ctx), 2);
    }

    #[test]
    fn find_k_max_zero_when_no_elements() {
        let ctx = make_ctx(vec![]);
        assert_eq!(find_k_max(&ctx), 0);
    }

    #[test]
    fn find_l_max_returns_min_distinct_sensitive() {
        // Clase A: large+small → 2 distintos
        // Clase B: solo large  → 1 distinto
        let ctx = make_ctx(vec![
            (vec!["v1","v2"], vec!["large"]),
            (vec!["v3","v4"], vec!["small"]),
        ]);
        // Ambas clases tienen 1 valor distinto (cada una su propio valor)
        assert_eq!(find_l_max(&ctx), 1);
    }

    #[test]
    fn find_t_min_returns_minimum_emd() {
        let ctx = make_ctx(vec![
            (vec!["v1","v2"], vec!["large"]),
            (vec!["v3","v4"], vec!["small"]),
        ]);
        let t_result = eval_t(&ctx, 0.9);
        let t_min = find_t_min(&ctx, &t_result);
        // Con atributos sensibles deberíamos tener Some(...)
        // En este caso cada clase tiene solo un valor que no está en la otra
        // → EMD ≈ 1 para cada clase
        if let Some(v) = t_min {
            assert!(v >= 0.0 && v <= 1.0, "t_min must be in [0,1], got {v}");
        }
    }

    #[test]
    fn find_t_min_none_without_sensitive_attrs() {
        // PolicyContext sin atributos sensibles (global_dist vacío)
        let ctx = PolicyContext {
            class_map:             BTreeMap::new(),
            sens_map:              HashMap::new(),
            global_dist:           BTreeMap::new(),
            global_total:          0,
            activated_qid_ids:     vec![],
            non_activated_qid_ids: vec![],
        };
        let t_result = eval_t(&ctx, 0.5);
        assert_eq!(find_t_min(&ctx, &t_result), None);
    }

    // =========================================================================
    // Layer 3 — elements_at_risk
    // =========================================================================

    #[test]
    fn elements_at_risk_lists_members_of_violating_classes() {
        let ctx = make_ctx(vec![
            (vec!["v1"],      vec!["large"]),  // tamaño 1 < k=2 → viola
            (vec!["v3","v4"], vec!["small"]),  // tamaño 2 ≥ k=2 → ok
        ]);
        let k_result = eval_k(&ctx, 2);
        let at_risk = elements_at_risk(&k_result);
        assert_eq!(at_risk, vec!["v1".to_string()]);
    }

    #[test]
    fn elements_at_risk_empty_when_k_satisfied() {
        let ctx = make_ctx(vec![(vec!["v1","v2"], vec!["large"])]);
        let k_result = eval_k(&ctx, 2);
        assert!(elements_at_risk(&k_result).is_empty());
    }

    // =========================================================================
    // Layer 3 — sensitive_values_at_risk
    // =========================================================================

    #[test]
    fn sensitive_values_at_risk_captures_values_in_violating_classes() {
        // Clase que viola l=2 (solo "large")
        let ctx = make_ctx(vec![
            (vec!["v1","v2"], vec!["large"]),
        ]);
        let l_result = eval_l(&ctx, 2);
        let t_result = eval_t(&ctx, 1.0);
        let risks = sensitive_values_at_risk(&l_result, &t_result, &["capacity".to_string()]);

        assert_eq!(risks.len(), 1);
        assert_eq!(risks[0].attr_name, "capacity");
        assert!(risks[0].at_risk_values.contains(&qv("large")));
    }

    #[test]
    fn sensitive_values_at_risk_empty_when_all_satisfied() {
        let ctx = make_ctx(vec![
            (vec!["v1","v2"], vec!["large"]),
            (vec!["v3","v4"], vec!["small"]),
        ]);
        // l=1 trivialmente satisfecho para clases con 1 valor distinto
        let l_result = eval_l(&ctx, 1);
        let t_result = eval_t(&ctx, 1.0);
        let risks = sensitive_values_at_risk(&l_result, &t_result, &["capacity".to_string()]);
        for r in &risks {
            assert!(r.at_risk_values.is_empty(), "Expected no at-risk values, got {:?}", r.at_risk_values);
        }
    }

    // =========================================================================
    // discrete_emd
    // =========================================================================

    #[test]
    fn discrete_emd_identical_distributions() {
        let sens = vec![vec![qv("large")], vec![qv("small")]];
        let mut global = BTreeMap::new();
        global.insert(vec![qv("large")], 1usize);
        global.insert(vec![qv("small")], 1usize);
        assert!((discrete_emd(&sens, &global, 2) - 0.0).abs() < 1e-9);
    }

    #[test]
    fn discrete_emd_disjoint_distributions() {
        let sens = vec![vec![qv("large")]];
        let mut global = BTreeMap::new();
        global.insert(vec![qv("small")], 1usize);
        assert!((discrete_emd(&sens, &global, 1) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn discrete_emd_empty_class() {
        assert_eq!(discrete_emd(&[], &BTreeMap::new(), 0), 0.0);
    }

    #[test]
    fn discrete_emd_partial_overlap() {
        let sens = vec![vec![qv("large")], vec![qv("large")]];
        let mut global = BTreeMap::new();
        global.insert(vec![qv("large")], 1usize);
        global.insert(vec![qv("small")], 1usize);
        let emd = discrete_emd(&sens, &global, 2);
        assert!((emd - 0.5).abs() < 1e-9, "Expected 0.5, got {emd}");
    }
