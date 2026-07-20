//! Unit tests for [`crate::kanon::activation`].
//!
//! Covers: [`predicates_compatible`], [`Matching::apply_to_filter`],
//! [`find_matchings`], and [`qid_is_activated`].
//! Includes cross-join cases and protected-variable reuse.

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

    /// Binding box containing an object variable O_V:{vehicle},
    /// an event variable E_S:{shipment}, and an
    /// O2E(E_S, O_V, wildcard) filter.
    /// Corresponds to the q1 pattern from the example.
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

    /// Binding box containing O_V, E_S and E_D (BB2 of the example).
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

    /// Minimum pattern: a vehicle variable and a departure variable, with O2E between them.
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

    /// Q1 pattern: vehicle + shipment with O2E wildcard.
    fn pattern_q1() -> Pattern {
        Pattern::try_from_box(&bbox_vehicle_shipment()).unwrap()
    }

    /// Complete QID q1 from the example.
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

    /// Wildcard (None) is compatible with any qualifier.
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

    /// Two different named qualifiers are not compatible.
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

    /// A named qualifier is compatible with itself.
    #[test]
    fn predicates_compatible_same_named_qualifier() {
        let f = Filter::O2E {
            object: ObjectVariable(0), event: EventVariable(0),
            qualifier: Some("primary".to_string()), filter_label: None,
        };
        assert!(predicates_compatible(&f, &f));
    }

    // =========================================================================
    // predicates_compatible — TBE / intervals
    // =========================================================================

    /// Intervals that overlap partially are compatible.
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

    /// Intervals that are disjoint are not compatible.
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

    /// An interval without a lower bound (−∞) overlaps with any interval.
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

    /// Both intervals without bounds (−∞, +∞) always overlap.
    #[test]
    fn predicates_compatible_tbe_both_unbounded() {
        let f = Filter::TimeBetweenEvents {
            from_event: EventVariable(0), to_event: EventVariable(1),
            min_seconds: None, max_seconds: None,
        };
        assert!(predicates_compatible(&f, &f));
    }

    /// Filters of different types are never compatible.
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

    /// `apply_to_filter` correctly renames the variables of an O2E filter.
    #[test]
    fn apply_to_filter_o2e_renames_variables() {
        // φ: pattern E(0)→box E(5),  pattern O(0)→box O(7)
        let phi = Matching {
            ev_map: [(EventVariable(0), EventVariable(5))].into(),
            ob_map: [(ObjectVariable(0), ObjectVariable(7))].into(),
        };
        let pf = Filter::O2E {
            object: ObjectVariable(0), event: EventVariable(0),
            qualifier: Some("primary".to_string()), filter_label: None,
        };
        let renamed = phi.apply_to_filter(&pf).unwrap();
        // `Filter` does not implement `PartialEq`; inspect the fields directly.
        match renamed {
            Filter::O2E { object, event, qualifier, .. } => {
                assert_eq!(object,    ObjectVariable(7), "object variable mismatch");
                assert_eq!(event,     EventVariable(5),  "event variable mismatch");
                assert_eq!(qualifier, Some("primary".to_string()), "qualifier mismatch");
            }
            other => panic!("Expected O2E filter, got {other:?}"),
        }
    }

    /// `apply_to_filter` returns None if a variable of the filter is not in φ.
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

    /// `apply_to_filter` with a non-structural filter returns None.
    #[test]
    fn apply_to_filter_non_structural_returns_none() {
        let phi = Matching {
            ev_map: HashMap::new(),
            ob_map: HashMap::new(),
        };
        // The fields of the `NotEqual` variant are named `var_1` and `var_2`.
        let non_structural = Filter::NotEqual {
            var_1: crate::binding_box::structs::Variable::Object(ObjectVariable(0)),
            var_2: crate::binding_box::structs::Variable::Object(ObjectVariable(1)),
        };
        assert!(phi.apply_to_filter(&non_structural).is_none());
    }

    // =========================================================================
    // find_matchings — basic cases
    // =========================================================================

    /// Pattern and box identical: exactly one matching (identity).
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

    /// Pattern with incompatible type: no matchings.
    #[test]
    fn find_matchings_type_mismatch_no_matchings() {
        // Pattern requests {truck} but the box only has {vehicle}
        let mut pat = pattern_q1();
        pat.object_vars.insert(ObjectVariable(0), ["truck".to_string()].into());
        let bbox = bbox_vehicle_shipment();
        assert!(find_matchings(&pat, &bbox).is_empty());
    }

    /// Empty pattern fits in any binding box — an empty matching.
    #[test]
    fn find_matchings_empty_pattern_always_matches() {
        let pat = Pattern::try_from_box(&empty_bbox()).unwrap();
        let matchings = find_matchings(&pat, &bbox_bb2());
        assert_eq!(matchings.len(), 1);
        assert!(matchings[0].ev_map.is_empty());
        assert!(matchings[0].ob_map.is_empty());
    }

    /// Pattern in empty box: no matchings (no variables to assign).
    #[test]
    fn find_matchings_non_empty_pattern_in_empty_box_no_match() {
        let pat = pattern_q1();
        let matchings = find_matchings(&pat, &empty_bbox());
        assert!(matchings.is_empty());
    }

    /// q1 is activated in BB2: the pattern (vehicle + shipment) matches
    /// the binding box (vehicle + shipment + departure),
    /// mapping only the shipment event.
    #[test]
    fn find_matchings_q1_pattern_in_bb2() {
        let pat = pattern_q1();
        let bbox = bbox_bb2();
        let matchings = find_matchings(&pat, &bbox);
        // Only one valid matching: E_S → E_S (shipment), not E_D (departure),
        // because the filter O2E(E_S, O_V, *) is not compatible with
        // O2E(E_D, O_V, *) when E_S is mapped to E_D.
        // The types do not match: {shipment} ≠ {departure}.
        assert_eq!(matchings.len(), 1);
        assert_eq!(matchings[0].ev_map[&EventVariable(0)], EventVariable(0));
    }

    // =========================================================================
    // Question 2A — Binding box with two independent pairs: v1-d1, v2-d2
    //
    // Pattern: vehicle(P_OV) + departure(P_EV), O2E(P_EV, P_OV, *)
    // Box:     v1:{vehicle}, v2:{vehicle}, d1:{departure}, d2:{departure}
    //          filters: O2E(d1,v1,*) and O2E(d2,v2,*)
    //
    // Expected valid matchings:
    //   φ1 = {OV→v1, EV→d1}
    //   φ2 = {OV→v2, EV→d2}.
    //
    // Cross matchings
    //   φ = {OV→v1, EV→d2}
    //   φ = {OV→v2, EV→d1}
    // must be discarded because O2E(d2,v1,*) and O2E(d1,v2,*)
    // do not exist in the binding box.
    // =========================================================================

    #[test]
    fn find_matchings_two_pairs_no_cross_join() {
        // Binding box with two independent pairs
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

        // Only φ1 and φ2 are valid; cross matchings are rejected by the
        // predicate compatibility check.
        assert_eq!(
            matchings.len(), 2,
            "Expected 2 matchings (one per pair), got {}: {matchings:?}",
            matchings.len()
        );

        // Verify that the two expected pairs are present (in any order).
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
    // Question 2B — Binding box with a shared vehicle: v1-d1 and v1-d2
    //
    // Pattern: vehicle(P_OV) + departure(P_EV), O2E(P_EV, P_OV, *)
    // Box:     v1:{vehicle}, d1:{departure}, d2:{departure}
    //          filters: O2E(d1,v1,*) and O2E(d2,v1,*)
    //
    // Expected valid matchings:
    //   φ1 = {OV→v1, EV→d1}
    //   φ2 = {OV→v1, EV→d2}.
    //
    // Injectivity is not violated: the pattern contains only one vehicle
    // variable, so v1 may be the image of that variable in both matchings.
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

        // Two matchings: one for each departure, both pointing to the same vehicle.
        assert_eq!(
            matchings.len(), 2,
            "Expected 2 matchings (two departures sharing v1), got {}: {matchings:?}",
            matchings.len()
        );

        // Both matchings should map to v1
        for m in &matchings {
            assert_eq!(
                m.ob_map[&ObjectVariable(0)], ObjectVariable(1),
                "Both matchings should map to v1"
            );
        }

        // The assigned departures should be d1 and d2 (in any order)
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

    /// q1 is activated in BB2 (which contains vehicle + shipment).
    #[test]
    fn qid_is_activated_q1_in_bb2() {
        assert!(qid_is_activated(&qid_q1(), &bbox_bb2()));
    }

    /// q1 is not activated in an empty box.
    #[test]
    fn qid_is_activated_q1_in_empty_box() {
        assert!(!qid_is_activated(&qid_q1(), &empty_bbox()));
    }

    /// q1 is not activated if the box has a vehicle but no shipment.
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
        // The pattern for q1 needs a shipment event, not a departure
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
