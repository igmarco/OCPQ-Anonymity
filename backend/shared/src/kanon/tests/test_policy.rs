//! Unit tests for [`crate::kanon::policy`].
//!
//! Covers: [`Pattern::try_from_box`], [`Pattern::all_event_vars`],
//! [`Pattern::all_object_vars`], [`QuasiIdentifier::validate`], and
//! [`AnonPolicy::validate`] / [`AnonPolicy::protected_type_set`].

use crate::binding_box::structs::{{
    BindingBox, EventVariable, Filter, ObjectVariable,
}};
use crate::kanon::policy::{{
    AnonPolicy, Pattern, ProtectedVar, QidAttribute, QuasiIdentifier, SourceVar,
}};
use std::collections::{{HashMap, HashSet}};

    // -------------------------------------------------------------------------
    // Helpers: reusable constructors for multiple tests
    // -------------------------------------------------------------------------

    /// Minimal binding box with one object variable, one event variable,
    /// and an O2E filter—represents the q1 pattern from the example.
    fn bbox_o2e() -> BindingBox {
        BindingBox {
            new_object_vars: [(ObjectVariable(0), ["vehicle".to_string()].into())].into(),
            new_event_vars:  [(EventVariable(0),  ["shipment".to_string()].into())].into(),
            filters: vec![Filter::O2E {
                object:       ObjectVariable(0),
                event:        EventVariable(0),
                qualifier:    None,
                filter_label: None,
            }],
            size_filters:  vec![],
            constraints:   vec![],
            ev_var_labels: HashMap::new(),
            ob_var_labels: HashMap::new(),
            labels:        vec![],
        }
    }

    /// Binding box containing the three structural filter types (O2E, O2O, TBE).

    fn bbox_all_structural() -> BindingBox {
        BindingBox {
            new_object_vars: [
                (ObjectVariable(0), ["vehicle".to_string()].into()),
                (ObjectVariable(1), ["depot".to_string()].into()),
            ].into(),
            new_event_vars: [
                (EventVariable(0), ["shipment".to_string()].into()),
                (EventVariable(1), ["departure".to_string()].into()),
            ].into(),
            filters: vec![
                Filter::O2E {
                    object: ObjectVariable(0), event: EventVariable(0),
                    qualifier: None, filter_label: None,
                },
                Filter::O2O {
                    object: ObjectVariable(0), other_object: ObjectVariable(1),
                    qualifier: Some("docked_at".to_string()), filter_label: None,
                },
                Filter::TimeBetweenEvents {
                    from_event: EventVariable(0), to_event: EventVariable(1),
                    min_seconds: Some(0.0), max_seconds: Some(86400.0),
                },
            ],
            size_filters:  vec![],
            constraints:   vec![],
            ev_var_labels: HashMap::new(),
            ob_var_labels: HashMap::new(),
            labels:        vec![],
        }
    }

    /// Valid QID for the example: protects `ObjectVariable(0)` (vehicle)
    /// and reads the `customer_segment` attribute from
    /// `EventVariable(0)` (shipment).
    fn valid_qid_q1() -> QuasiIdentifier {
        let pattern = Pattern::try_from_box(&bbox_o2e()).unwrap();
        QuasiIdentifier {
            id:            "q1".to_string(),
            pattern,
            protected_var: ProtectedVar::Object(ObjectVariable(0)),
            source_var:    SourceVar::Event(EventVariable(0)),
            attribute:     QidAttribute::Named("customer_segment".to_string()),
        }
    }

    /// Minimal QID protecting an event (to cover the Event branch of
    /// `ProtectedVar`/`SourceVar`).
    fn valid_qid_event_protected() -> QuasiIdentifier {
        let bbox = BindingBox {
            new_object_vars: HashMap::new(),
            new_event_vars: [
                (EventVariable(0), ["shipment".to_string()].into()),
                (EventVariable(1), ["departure".to_string()].into()),
            ].into(),
            filters: vec![Filter::TimeBetweenEvents {
                from_event:  EventVariable(0),
                to_event:    EventVariable(1),
                min_seconds: None,
                max_seconds: None,
            }],
            size_filters:  vec![],
            constraints:   vec![],
            ev_var_labels: HashMap::new(),
            ob_var_labels: HashMap::new(),
            labels:        vec![],
        };
        let pattern = Pattern::try_from_box(&bbox).unwrap();
        QuasiIdentifier {
            id:            "q_ev".to_string(),
            pattern,
            protected_var: ProtectedVar::Event(EventVariable(0)),
            source_var:    SourceVar::Event(EventVariable(1)),
            attribute:     QidAttribute::Timestamp,
        }
    }

    /// Complete policy from the paper example (k = 2, l = 2, t = 1.0).
    fn example_policy() -> AnonPolicy {
        // q2: protects the vehicle and reads the Id of the departure event
        let bbox_q2 = BindingBox {
            new_object_vars: [(ObjectVariable(0), ["vehicle".to_string()].into())].into(),
            new_event_vars:  [(EventVariable(1), ["departure".to_string()].into())].into(),
            filters: vec![Filter::O2E {
                object: ObjectVariable(0), event: EventVariable(1),
                qualifier: None, filter_label: None,
            }],
            size_filters:  vec![],
            constraints:   vec![],
            ev_var_labels: HashMap::new(),
            ob_var_labels: HashMap::new(),
            labels:        vec![],
        };
        let pattern_q2 = Pattern::try_from_box(&bbox_q2).unwrap();
        let qid2 = QuasiIdentifier {
            id:            "q2".to_string(),
            pattern:       pattern_q2,
            protected_var: ProtectedVar::Object(ObjectVariable(0)),
            source_var:    SourceVar::Event(EventVariable(1)),
            attribute:     QidAttribute::Id,
        };

        AnonPolicy {
            qids:            vec![valid_qid_q1(), qid2],
            sensitive_attrs: vec!["capacity".to_string()],
            k: 2,
            l: 2,
            t: 1.0,
        }
    }

    // =========================================================================
    // Pattern::try_from_box
    // =========================================================================

    /// A binding box containing the three structural filter types should produce
    /// a `Pattern` containing exactly those filters.
    #[test]
    fn pattern_try_from_box_structural_filters_ok() {
        let bbox = bbox_all_structural();
        let result = Pattern::try_from_box(&bbox);
        assert!(result.is_ok(), "Expected Ok, got: {:?}", result);
        let pat = result.unwrap();
        assert_eq!(pat.filters.len(), 3);
    }

    /// A binding box containing a non-structural filter should be rejected.
    ///
    /// We use `Filter::NotEqual` as an example of a filter that does not belong
    /// to BASIC_L.
    #[test]
    fn pattern_try_from_box_non_structural_filter_err() {
        let mut bbox = bbox_o2e();
        // Add a non-structural filter: NotEqual between two object variables
        bbox.filters.push(Filter::NotEqual {
            var_1: crate::binding_box::structs::Variable::Object(ObjectVariable(0)),
            var_2: crate::binding_box::structs::Variable::Object(ObjectVariable(0)),
        });
        let result = Pattern::try_from_box(&bbox);
        assert!(
            result.is_err(),
            "Expected Err for non-structural filter, got Ok"
        );
        let msg = result.unwrap_err();
        assert!(
            msg.contains("Pattern may only contain"),
            "Error message should mention restriction; got: {msg}"
        );
    }

    /// A completely empty binding box (without variables or filters) should
    /// produce an empty `Pattern` without error.
    #[test]
    fn pattern_try_from_box_empty_bbox_ok() {
        let bbox = BindingBox {
            new_object_vars: HashMap::new(),
            new_event_vars:  HashMap::new(),
            filters:         vec![],
            size_filters:    vec![],
            constraints:     vec![],
            ev_var_labels:   HashMap::new(),
            ob_var_labels:   HashMap::new(),
            labels:          vec![],
        };
        let result = Pattern::try_from_box(&bbox);
        assert!(result.is_ok());
        let pat = result.unwrap();
        assert!(pat.filters.is_empty());
        assert!(pat.event_vars.is_empty());
        assert!(pat.object_vars.is_empty());
    }

    /// `try_from_box` must faithfully copy `new_event_vars` and
    /// `new_object_vars`.
    #[test]
    fn pattern_try_from_box_copies_vars_faithfully() {
        let bbox = bbox_o2e();
        let pat = Pattern::try_from_box(&bbox).unwrap();

        assert!(pat.event_vars.contains_key(&EventVariable(0)));
        assert_eq!(
            pat.event_vars[&EventVariable(0)],
            ["shipment".to_string()].into()
        );
        assert!(pat.object_vars.contains_key(&ObjectVariable(0)));
        assert_eq!(
            pat.object_vars[&ObjectVariable(0)],
            ["vehicle".to_string()].into()
        );
    }

    // =========================================================================
    // Pattern::all_event_vars / all_object_vars
    // =========================================================================

    /// `all_event_vars` must return exactly the keys of `event_vars`.
    #[test]
    fn pattern_all_event_vars_returns_correct_set() {
        let bbox = bbox_all_structural();
        let pat = Pattern::try_from_box(&bbox).unwrap();

        let vars: HashSet<EventVariable> = pat.all_event_vars().collect();
        assert_eq!(
            vars,
            [EventVariable(0), EventVariable(1)].into()
        );
    }

    /// `all_object_vars` must return exactly the keys of `object_vars`.
    #[test]
    fn pattern_all_object_vars_returns_correct_set() {
        let bbox = bbox_all_structural();
        let pat = Pattern::try_from_box(&bbox).unwrap();

        let vars: HashSet<ObjectVariable> = pat.all_object_vars().collect();
        assert_eq!(
            vars,
            [ObjectVariable(0), ObjectVariable(1)].into()
        );
    }

    // =========================================================================
    // QuasiIdentifier::validate
    // =========================================================================

    /// A QID whose protected and source variables are correctly declared in the
    /// pattern should validate successfully.
    #[test]
    fn qid_validate_ok() {
        assert!(valid_qid_q1().validate().is_ok());
    }

    /// A QID where the protected variable (object) is not in the pattern should
    /// return Err with a message mentioning the variable and the QID.
    #[test]
    fn qid_validate_err_protected_object_missing() {
        let mut qid = valid_qid_q1();
        qid.protected_var = ProtectedVar::Object(ObjectVariable(99)); // not declared
        let err = qid.validate().unwrap_err();
        assert!(
            err.contains("protected object variable"),
            "Error should mention 'protected object variable'; got: {err}"
        );
        assert!(err.contains("q1"), "Error should mention QID id; got: {err}");
    }

    /// A QID where the protected variable (event) is not in the pattern should
    /// return Err.
    #[test]
    fn qid_validate_err_protected_event_missing() {
        let mut qid = valid_qid_event_protected();
        qid.protected_var = ProtectedVar::Event(EventVariable(99));
        let err = qid.validate().unwrap_err();
        assert!(err.contains("protected event variable"), "{err}");
    }

    /// A QID where the source variable (event) is not in the pattern should
    /// return Err.
    #[test]
    fn qid_validate_err_source_event_missing() {
        let mut qid = valid_qid_q1();
        qid.source_var = SourceVar::Event(EventVariable(99)); // not declared
        let err = qid.validate().unwrap_err();
        assert!(
            err.contains("source event variable"),
            "Error should mention 'source event variable'; got: {err}"
        );
    }

    /// A QID where the source variable (object) is not in the pattern should
    /// return Err.
    #[test]
    fn qid_validate_err_source_object_missing() {
        let mut qid = valid_qid_q1();
        // Cambiamos source_var a un objeto no declarado
        qid.source_var = SourceVar::Object(ObjectVariable(99));
        let err = qid.validate().unwrap_err();
        assert!(err.contains("source object variable"), "{err}");
    }

    /// It is valid for protected_var and source_var to point to the same variable
    /// (an element identifies itself).
    #[test]
    fn qid_validate_ok_source_equals_protected() {
        let mut qid = valid_qid_q1();
        // Make source_var point to the same object as protected_var
        qid.source_var = SourceVar::Object(ObjectVariable(0));
        qid.attribute  = QidAttribute::Id;
        assert!(qid.validate().is_ok());
    }

    // =========================================================================
    // AnonPolicy::validate
    // =========================================================================

    /// A policy without QIDs should return Err.
    #[test]
    fn policy_validate_err_no_qids() {
        let policy = AnonPolicy {
            qids:            vec![],
            sensitive_attrs: vec![],
            k: 2,
            l: 0,
            t: 1.0,
        };
        let err = policy.validate().unwrap_err();
        assert!(err.contains("at least one QID"), "{err}");
    }

    /// A QID with an invalid protected variable should propagate as Err.
    #[test]
    fn policy_validate_err_invalid_qid_propagated() {
        let mut qid = valid_qid_q1();
        qid.protected_var = ProtectedVar::Object(ObjectVariable(99)); // invalid
        let policy = AnonPolicy {
            qids:            vec![qid],
            sensitive_attrs: vec![],
            k: 2,
            l: 0,
            t: 1.0,
        };
        assert!(policy.validate().is_err());
    }

    /// Two QIDs with different τ_prot values should produce `Err`.
    #[test]
    fn policy_validate_err_tau_prot_mismatch() {
        // q1 protects the vehicle (`ObjectVariable(0)`)
        let q1 = valid_qid_q1();

        // q_other protects the shipment (`EventVariable(0)`) in an
        // event-only pattern
        let bbox_ev = BindingBox {
            new_object_vars: HashMap::new(),
            new_event_vars: [
                (EventVariable(0), ["shipment".to_string()].into()),
                (EventVariable(1), ["departure".to_string()].into()),
            ].into(),
            filters: vec![Filter::TimeBetweenEvents {
                from_event: EventVariable(0), to_event: EventVariable(1),
                min_seconds: None, max_seconds: None,
            }],
            size_filters:  vec![],
            constraints:   vec![],
            ev_var_labels: HashMap::new(),
            ob_var_labels: HashMap::new(),
            labels:        vec![],
        };
        let q_other = QuasiIdentifier {
            id:            "q_other".to_string(),
            pattern:       Pattern::try_from_box(&bbox_ev).unwrap(),
            protected_var: ProtectedVar::Event(EventVariable(0)), // Different type
            source_var:    SourceVar::Event(EventVariable(1)),
            attribute:     QidAttribute::Timestamp,
        };

        let policy = AnonPolicy {
            qids:            vec![q1, q_other],
            sensitive_attrs: vec![],
            k: 2,
            l: 0,
            t: 1.0,
        };
        let err = policy.validate().unwrap_err();
        assert!(
            err.contains("agree on τ_prot"),
            "Error should mention τ_prot; got: {err}"
        );
    }

    /// k = 1 is the minimum valid value.
    #[test]
    fn policy_validate_ok_k_equals_one() {
        let mut policy = example_policy();
        policy.k = 1;
        assert!(policy.validate().is_ok());
    }

    /// t > 1.0 must be rejected.
    #[test]
    fn policy_validate_err_t_above_one() {
        let mut policy = example_policy();
        policy.t = 1.1;
        let err = policy.validate().unwrap_err();
        assert!(err.contains("t must be in [0, 1]"), "{err}");
    }

    /// t < 0.0 must be rejected.
    #[test]
    fn policy_validate_err_t_below_zero() {
        let mut policy = example_policy();
        policy.t = -0.1;
        let err = policy.validate().unwrap_err();
        assert!(err.contains("t must be in [0, 1]"), "{err}");
    }

    /// The full example policy (k=2, l=2, t=1.0) should validate without
    /// error and with the correct parameters.
    #[test]
    fn policy_validate_ok_full_example() {
        let policy = example_policy();
        assert!(policy.validate().is_ok());
        assert_eq!(policy.k, 2);
        assert_eq!(policy.l, 2);
        assert!((policy.t - 1.0).abs() < f64::EPSILON);
        assert_eq!(policy.sensitive_attrs, vec!["capacity".to_string()]);
    }

    // =========================================================================
    // AnonPolicy::protected_types_of / protected_type_set
    // =========================================================================

    /// `protected_types_of` for a QID with an object-protected variable
    /// should return the set of types for that object.
    #[test]
    fn protected_types_of_object_var() {
        let policy = example_policy();
        let types = policy.protected_types_of(&policy.qids[0]);
        assert_eq!(types, ["vehicle".to_string()].into());
    }

    /// `protected_types_of` for a QID with an event-protected variable
    /// should return the set of types for that event.
    #[test]
    fn protected_types_of_event_var() {
        let qid = valid_qid_event_protected();
        let policy = AnonPolicy {
            qids:            vec![qid],
            sensitive_attrs: vec![],
            k: 1,
            l: 0,
            t: 1.0,
        };
        let types = policy.protected_types_of(&policy.qids[0]);
        assert_eq!(types, ["shipment".to_string()].into());
    }

    /// `protected_type_set` should return the same set as
    /// `protected_types_of` applied to the first QID.
    #[test]
    fn protected_type_set_matches_first_qid() {
        let policy = example_policy();
        let from_set  = policy.protected_type_set();
        let from_first = policy.protected_types_of(&policy.qids[0]);
        assert_eq!(from_set, from_first);
    }

    /// `protected_type_set` in a policy with no QIDs (built directly,
    /// without passing through `validate`) should return an empty set without panicking.
    #[test]
    fn protected_type_set_empty_when_no_qids() {
        let policy = AnonPolicy {
            qids:            vec![],
            sensitive_attrs: vec![],
            k: 1,
            l: 0,
            t: 1.0,
        };
        assert!(policy.protected_type_set().is_empty());
    }
