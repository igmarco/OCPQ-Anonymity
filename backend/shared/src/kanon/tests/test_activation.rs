//! Tests unitarios de [`crate::kanon::activation`].
//!
//! Cubren: [`predicates_compatible`], [`Matching::apply_to_filter`],
//! [`find_matchings`] y [`qid_is_activated`].
//! Incluye los casos de cross-join y reutilización de variable protegida.

use crate::binding_box::structs::{{BindingBox, Filter, EventVariable, ObjectVariable}};
use crate::kanon::activation::{{
    find_matchings, Matching, predicates_compatible, qid_is_activated,
}};
use crate::kanon::policy::{{
    Pattern, ProtectedVar, QidAttribute, QuasiIdentifier, SourceVar,
}};
use std::collections::HashMap;

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    fn empty_bbox() -> BindingBox {
        BindingBox {
            new_object_vars: HashMap::new(),
            new_event_vars:  HashMap::new(),
            filters:         vec![],
            size_filters:    vec![],
            constraints:     vec![],
            ev_var_labels:   HashMap::new(),
            ob_var_labels:   HashMap::new(),
            labels:          vec![],
        }
    }

    /// Binding box con una variable de objeto O_V:{vehicle},
    /// una de evento E_S:{shipment} y un filtro O2E(E_S, O_V, wildcard).
    /// Corresponde al patrón de q1 del ejemplo.
    fn bbox_vehicle_shipment() -> BindingBox {
        BindingBox {
            new_object_vars: [(ObjectVariable(0), ["vehicle".to_string()].into())].into(),
            new_event_vars:  [(EventVariable(0),  ["shipment".to_string()].into())].into(),
            filters: vec![Filter::O2E {
                object:       ObjectVariable(0),
                event:        EventVariable(0),
                qualifier:    None,
                filter_label: None,
            }],
            ..empty_bbox()
        }
    }

    /// Binding box con O_V, E_S y E_D (BB2 del ejemplo).
    fn bbox_bb2() -> BindingBox {
        BindingBox {
            new_object_vars: [(ObjectVariable(0), ["vehicle".to_string()].into())].into(),
            new_event_vars: [
                (EventVariable(0), ["shipment".to_string()].into()),
                (EventVariable(1), ["departure".to_string()].into()),
            ].into(),
            filters: vec![
                Filter::O2E {
                    object: ObjectVariable(0), event: EventVariable(0),
                    qualifier: None, filter_label: None,
                },
                Filter::O2E {
                    object: ObjectVariable(0), event: EventVariable(1),
                    qualifier: None, filter_label: None,
                },
            ],
            ..empty_bbox()
        }
    }

    /// Patrón mínimo: una variable de vehículo y una de departure, con O2E entre ambas.
    fn pattern_vehicle_departure() -> Pattern {
        let bbox = BindingBox {
            new_object_vars: [(ObjectVariable(0), ["vehicle".to_string()].into())].into(),
            new_event_vars:  [(EventVariable(0),  ["departure".to_string()].into())].into(),
            filters: vec![Filter::O2E {
                object:       ObjectVariable(0),
                event:        EventVariable(0),
                qualifier:    None,
                filter_label: None,
            }],
            ..empty_bbox()
        };
        Pattern::try_from_box(&bbox).unwrap()
    }

    /// Patrón de q1: vehicle + shipment con O2E wildcard.
    fn pattern_q1() -> Pattern {
        Pattern::try_from_box(&bbox_vehicle_shipment()).unwrap()
    }

    /// QID q1 completo del ejemplo.
    fn qid_q1() -> QuasiIdentifier {
        QuasiIdentifier {
            id:            "q1".to_string(),
            pattern:       pattern_q1(),
            protected_var: ProtectedVar::Object(ObjectVariable(0)),
            source_var:    SourceVar::Event(EventVariable(0)),
            attribute:     QidAttribute::Named("customer_segment".to_string()),
        }
    }

    // =========================================================================
    // predicates_compatible — qualifiers
    // =========================================================================

    /// Wildcard (None) es compatible con cualquier qualifier.
    #[test]
    fn predicates_compatible_wildcard_both() {
        let f1 = Filter::O2E {
            object: ObjectVariable(0), event: EventVariable(0),
            qualifier: None, filter_label: None,
        };
        let f2 = Filter::O2E {
            object: ObjectVariable(0), event: EventVariable(0),
            qualifier: None, filter_label: None,
        };
        assert!(predicates_compatible(&f1, &f2));
    }

    #[test]
    fn predicates_compatible_wildcard_with_named() {
        let wildcard = Filter::O2E {
            object: ObjectVariable(0), event: EventVariable(0),
            qualifier: None, filter_label: None,
        };
        let named = Filter::O2E {
            object: ObjectVariable(0), event: EventVariable(0),
            qualifier: Some("primary".to_string()), filter_label: None,
        };
        // wildcard en el patrón, named en el box
        assert!(predicates_compatible(&wildcard, &named));
        // named en el patrón, wildcard en el box
        assert!(predicates_compatible(&named, &wildcard));
    }

    /// Dos qualifiers distintos no son compatibles.
    #[test]
    fn predicates_compatible_different_named_qualifiers() {
        let primary = Filter::O2E {
            object: ObjectVariable(0), event: EventVariable(0),
            qualifier: Some("primary".to_string()), filter_label: None,
        };
        let backup = Filter::O2E {
            object: ObjectVariable(0), event: EventVariable(0),
            qualifier: Some("backup".to_string()), filter_label: None,
        };
        assert!(!predicates_compatible(&primary, &backup));
    }

    /// El mismo qualifier named es compatible consigo mismo.
    #[test]
    fn predicates_compatible_same_named_qualifier() {
        let f = Filter::O2E {
            object: ObjectVariable(0), event: EventVariable(0),
            qualifier: Some("primary".to_string()), filter_label: None,
        };
        assert!(predicates_compatible(&f, &f));
    }

    // =========================================================================
    // predicates_compatible — TBE / intervalos
    // =========================================================================

    /// Intervalos que se solapan parcialmente son compatibles.
    #[test]
    fn predicates_compatible_tbe_intervals_overlap() {
        let f1 = Filter::TimeBetweenEvents {
            from_event: EventVariable(0), to_event: EventVariable(1),
            min_seconds: Some(0.0), max_seconds: Some(3600.0),
        };
        let f2 = Filter::TimeBetweenEvents {
            from_event: EventVariable(0), to_event: EventVariable(1),
            min_seconds: Some(1800.0), max_seconds: Some(7200.0),
        };
        assert!(predicates_compatible(&f1, &f2)); // solape [1800, 3600]
    }

    /// Intervalos disjuntos no son compatibles.
    #[test]
    fn predicates_compatible_tbe_intervals_disjoint() {
        let f1 = Filter::TimeBetweenEvents {
            from_event: EventVariable(0), to_event: EventVariable(1),
            min_seconds: Some(0.0), max_seconds: Some(100.0),
        };
        let f2 = Filter::TimeBetweenEvents {
            from_event: EventVariable(0), to_event: EventVariable(1),
            min_seconds: Some(200.0), max_seconds: Some(300.0),
        };
        assert!(!predicates_compatible(&f1, &f2));
    }

    /// Un intervalo sin cota inferior (−∞) solapa cualquier intervalo.
    #[test]
    fn predicates_compatible_tbe_unbounded_lower() {
        let f1 = Filter::TimeBetweenEvents {
            from_event: EventVariable(0), to_event: EventVariable(1),
            min_seconds: None, max_seconds: Some(50.0),
        };
        let f2 = Filter::TimeBetweenEvents {
            from_event: EventVariable(0), to_event: EventVariable(1),
            min_seconds: Some(100.0), max_seconds: Some(200.0),
        };
        // [−∞, 50] ∩ [100, 200] = ∅  → NO compatible
        assert!(!predicates_compatible(&f1, &f2));
    }

    /// Ambos intervalos sin cotas (−∞, +∞) siempre solapan.
    #[test]
    fn predicates_compatible_tbe_both_unbounded() {
        let f = Filter::TimeBetweenEvents {
            from_event: EventVariable(0), to_event: EventVariable(1),
            min_seconds: None, max_seconds: None,
        };
        assert!(predicates_compatible(&f, &f));
    }

    /// Filtros de tipo distinto nunca son compatibles.
    #[test]
    fn predicates_compatible_different_kinds() {
        let o2e = Filter::O2E {
            object: ObjectVariable(0), event: EventVariable(0),
            qualifier: None, filter_label: None,
        };
        let tbe = Filter::TimeBetweenEvents {
            from_event: EventVariable(0), to_event: EventVariable(1),
            min_seconds: None, max_seconds: None,
        };
        assert!(!predicates_compatible(&o2e, &tbe));
    }

    // =========================================================================
    // Matching::apply_to_filter
    // =========================================================================

    /// apply_to_filter renombra correctamente las variables de un filtro O2E.
    #[test]
    fn apply_to_filter_o2e_renames_variables() {
        // φ: patrón E(0)→box E(5),  patrón O(0)→box O(7)
        let phi = Matching {
            ev_map: [(EventVariable(0), EventVariable(5))].into(),
            ob_map: [(ObjectVariable(0), ObjectVariable(7))].into(),
        };
        let pf = Filter::O2E {
            object: ObjectVariable(0), event: EventVariable(0),
            qualifier: Some("primary".to_string()), filter_label: None,
        };
        let renamed = phi.apply_to_filter(&pf).unwrap();
        // Filter no implementa PartialEq; inspeccionamos los campos directamente.
        match renamed {
            Filter::O2E { object, event, qualifier, .. } => {
                assert_eq!(object,    ObjectVariable(7), "object variable mismatch");
                assert_eq!(event,     EventVariable(5),  "event variable mismatch");
                assert_eq!(qualifier, Some("primary".to_string()), "qualifier mismatch");
            }
            other => panic!("Expected O2E filter, got {other:?}"),
        }
    }

    /// apply_to_filter devuelve None si una variable del filtro no está en φ.
    #[test]
    fn apply_to_filter_missing_variable_returns_none() {
        let phi = Matching {
            ev_map: HashMap::new(), // E(0) no está mapeada
            ob_map: [(ObjectVariable(0), ObjectVariable(0))].into(),
        };
        let pf = Filter::O2E {
            object: ObjectVariable(0), event: EventVariable(0),
            qualifier: None, filter_label: None,
        };
        assert!(phi.apply_to_filter(&pf).is_none());
    }

    /// apply_to_filter con un filtro no estructural devuelve None.
    #[test]
    fn apply_to_filter_non_structural_returns_none() {
        let phi = Matching {
            ev_map: HashMap::new(),
            ob_map: HashMap::new(),
        };
        // Los campos de la variante NotEqual se llaman var_1 y var_2.
        let non_structural = Filter::NotEqual {
            var_1: crate::binding_box::structs::Variable::Object(ObjectVariable(0)),
            var_2: crate::binding_box::structs::Variable::Object(ObjectVariable(1)),
        };
        assert!(phi.apply_to_filter(&non_structural).is_none());
    }

    // =========================================================================
    // find_matchings — casos básicos
    // =========================================================================

    /// Patrón y box idénticos: exactamente un matching (identidad).
    #[test]
    fn find_matchings_identical_pattern_and_box() {
        let pat = pattern_q1();
        let bbox = bbox_vehicle_shipment();
        let matchings = find_matchings(&pat, &bbox);
        assert_eq!(matchings.len(), 1);
        let m = &matchings[0];
        assert_eq!(m.ob_map[&ObjectVariable(0)], ObjectVariable(0));
        assert_eq!(m.ev_map[&EventVariable(0)],  EventVariable(0));
    }

    /// Patrón con tipo incompatible: ningún matching.
    #[test]
    fn find_matchings_type_mismatch_no_matchings() {
        // Patrón pide {truck} pero el box solo tiene {vehicle}
        let mut pat = pattern_q1();
        pat.object_vars.insert(ObjectVariable(0), ["truck".to_string()].into());
        let bbox = bbox_vehicle_shipment();
        assert!(find_matchings(&pat, &bbox).is_empty());
    }

    /// Patrón vacío encaja en cualquier binding box — un matching vacío.
    #[test]
    fn find_matchings_empty_pattern_always_matches() {
        let pat = Pattern::try_from_box(&empty_bbox()).unwrap();
        let matchings = find_matchings(&pat, &bbox_bb2());
        assert_eq!(matchings.len(), 1);
        assert!(matchings[0].ev_map.is_empty());
        assert!(matchings[0].ob_map.is_empty());
    }

    /// Patrón en box vacío: ningún matching (no hay variables que asignar).
    #[test]
    fn find_matchings_non_empty_pattern_in_empty_box_no_match() {
        let pat = pattern_q1();
        let matchings = find_matchings(&pat, &empty_bbox());
        assert!(matchings.is_empty());
    }

    /// q1 activa en BB2: el patrón (vehicle+shipment) encaja en el box
    /// (vehicle+shipment+departure), mapeando solo shipment.
    #[test]
    fn find_matchings_q1_pattern_in_bb2() {
        let pat = pattern_q1();
        let bbox = bbox_bb2();
        let matchings = find_matchings(&pat, &bbox);
        // Solo un matching válido: E_S→E_S (shipment), no E_D (departure)
        // porque el filtro O2E(E_S,O_V,*) no es compatible con O2E(E_D,O_V,*)
        // cuando E_S se mapea a E_D — los tipos no coinciden: {shipment}≠{departure}
        assert_eq!(matchings.len(), 1);
        assert_eq!(matchings[0].ev_map[&EventVariable(0)], EventVariable(0));
    }

    // =========================================================================
    // Pregunta 2A — Box con dos pares v1-d1, v2-d2 sin cruce
    //
    // Patrón: vehicle(P_OV) + departure(P_EV), O2E(P_EV, P_OV, *)
    // Box:    v1:{vehicle}, v2:{vehicle}, d1:{departure}, d2:{departure}
    //         filtros: O2E(d1,v1,*) y O2E(d2,v2,*)
    //
    // Matchings válidos esperados: φ1={OV→v1,EV→d1} y φ2={OV→v2,EV→d2}.
    // Los cruces φ={OV→v1,EV→d2} y φ={OV→v2,EV→d1} deben descartarse
    // porque O2E(d2,v1,*) y O2E(d1,v2,*) no existen en el box.
    // =========================================================================

    #[test]
    fn find_matchings_two_pairs_no_cross_join() {
        // Box con dos pares disjuntos
        let bbox = BindingBox {
            new_object_vars: [
                (ObjectVariable(1), ["vehicle".to_string()].into()),
                (ObjectVariable(2), ["vehicle".to_string()].into()),
            ].into(),
            new_event_vars: [
                (EventVariable(1), ["departure".to_string()].into()),
                (EventVariable(2), ["departure".to_string()].into()),
            ].into(),
            filters: vec![
                Filter::O2E {
                    object: ObjectVariable(1), event: EventVariable(1),
                    qualifier: None, filter_label: None,
                },
                Filter::O2E {
                    object: ObjectVariable(2), event: EventVariable(2),
                    qualifier: None, filter_label: None,
                },
            ],
            ..empty_bbox()
        };

        let pat = pattern_vehicle_departure();
        let matchings = find_matchings(&pat, &bbox);

        // Solo φ1 y φ2 son válidos; los cruces se descartan por el predicate check
        assert_eq!(
            matchings.len(), 2,
            "Expected 2 matchings (one per pair), got {}: {matchings:?}",
            matchings.len()
        );

        // Comprobar que los matchings son los dos pares correctos (en cualquier orden)
        let pairs: std::collections::HashSet<(ObjectVariable, EventVariable)> = matchings
            .iter()
            .map(|m| {
                let ob = m.ob_map[&ObjectVariable(0)];
                let ev = m.ev_map[&EventVariable(0)];
                (ob, ev)
            })
            .collect();

        assert!(pairs.contains(&(ObjectVariable(1), EventVariable(1))),
            "Missing pair (v1, d1) in {pairs:?}");
        assert!(pairs.contains(&(ObjectVariable(2), EventVariable(2))),
            "Missing pair (v2, d2) in {pairs:?}");
    }

    // =========================================================================
    // Pregunta 2B — Box con v1 compartido: v1-d1 y v1-d2
    //
    // Patrón: vehicle(P_OV) + departure(P_EV), O2E(P_EV, P_OV, *)
    // Box:    v1:{vehicle}, d1:{departure}, d2:{departure}
    //         filtros: O2E(d1,v1,*) y O2E(d2,v1,*)
    //
    // Matchings válidos esperados: φ1={OV→v1,EV→d1} y φ2={OV→v1,EV→d2}.
    // La injectividad no se viola: solo hay una variable de vehículo
    // en el patrón, así que v1 puede ser imagen en ambos matchings.
    // =========================================================================

    #[test]
    fn find_matchings_shared_vehicle_two_departures() {
        let bbox = BindingBox {
            new_object_vars: [
                (ObjectVariable(1), ["vehicle".to_string()].into()),
            ].into(),
            new_event_vars: [
                (EventVariable(1), ["departure".to_string()].into()),
                (EventVariable(2), ["departure".to_string()].into()),
            ].into(),
            filters: vec![
                Filter::O2E {
                    object: ObjectVariable(1), event: EventVariable(1),
                    qualifier: None, filter_label: None,
                },
                Filter::O2E {
                    object: ObjectVariable(1), event: EventVariable(2),
                    qualifier: None, filter_label: None,
                },
            ],
            ..empty_bbox()
        };

        let pat = pattern_vehicle_departure();
        let matchings = find_matchings(&pat, &bbox);

        // Dos matchings: uno por departure, ambos apuntando al mismo vehículo
        assert_eq!(
            matchings.len(), 2,
            "Expected 2 matchings (two departures sharing v1), got {}: {matchings:?}",
            matchings.len()
        );

        // Ambos matchings deben tener OV→v1
        for m in &matchings {
            assert_eq!(
                m.ob_map[&ObjectVariable(0)], ObjectVariable(1),
                "Both matchings should map to v1"
            );
        }

        // Los departures asignados deben ser d1 y d2 (en cualquier orden)
        let ev_targets: std::collections::HashSet<EventVariable> = matchings
            .iter()
            .map(|m| m.ev_map[&EventVariable(0)])
            .collect();
        assert!(ev_targets.contains(&EventVariable(1)));
        assert!(ev_targets.contains(&EventVariable(2)));
    }

    // =========================================================================
    // qid_is_activated
    // =========================================================================

    /// q1 se activa en BB2 (que contiene vehicle + shipment).
    #[test]
    fn qid_is_activated_q1_in_bb2() {
        assert!(qid_is_activated(&qid_q1(), &bbox_bb2()));
    }

    /// q1 no se activa en un box vacío.
    #[test]
    fn qid_is_activated_q1_in_empty_box() {
        assert!(!qid_is_activated(&qid_q1(), &empty_bbox()));
    }

    /// q1 no se activa si el box tiene vehicle pero no shipment.
    #[test]
    fn qid_is_activated_q1_missing_event_type() {
        let bbox = BindingBox {
            new_object_vars: [(ObjectVariable(0), ["vehicle".to_string()].into())].into(),
            new_event_vars:  [(EventVariable(0), ["departure".to_string()].into())].into(),
            filters: vec![Filter::O2E {
                object: ObjectVariable(0), event: EventVariable(0),
                qualifier: None, filter_label: None,
            }],
            ..empty_bbox()
        };
        // El patrón de q1 necesita un evento de tipo shipment, no departure
        assert!(!qid_is_activated(&qid_q1(), &bbox));
    }

    // =========================================================================
    // apply_to_ev_var / apply_to_ob_var
    // =========================================================================

    #[test]
    fn apply_to_ev_var_present() {
        let phi = Matching {
            ev_map: [(EventVariable(0), EventVariable(3))].into(),
            ob_map: HashMap::new(),
        };
        assert_eq!(phi.apply_to_ev_var(EventVariable(0)), Some(EventVariable(3)));
    }

    #[test]
    fn apply_to_ev_var_absent() {
        let phi = Matching { ev_map: HashMap::new(), ob_map: HashMap::new() };
        assert_eq!(phi.apply_to_ev_var(EventVariable(0)), None);
    }

    #[test]
    fn apply_to_ob_var_present() {
        let phi = Matching {
            ev_map: HashMap::new(),
            ob_map: [(ObjectVariable(0), ObjectVariable(5))].into(),
        };
        assert_eq!(phi.apply_to_ob_var(ObjectVariable(0)), Some(ObjectVariable(5)));
    }
