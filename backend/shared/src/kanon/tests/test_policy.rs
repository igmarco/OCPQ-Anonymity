//! Tests unitarios de [`crate::kanon::policy`].
//!
//! Cubren: [`Pattern::try_from_box`], [`Pattern::all_event_vars`],
//! [`Pattern::all_object_vars`], [`QuasiIdentifier::validate`] y
//! [`AnonPolicy::validate`] / [`AnonPolicy::protected_type_set`].

use crate::binding_box::structs::{{
    BindingBox, EventVariable, Filter, ObjectVariable,
}};
use crate::kanon::policy::{{
    AnonPolicy, Pattern, ProtectedVar, QidAttribute, QuasiIdentifier, SourceVar,
}};
use std::collections::{{HashMap, HashSet}};

    // -------------------------------------------------------------------------
    // Helpers: constructores reutilizables en múltiples tests
    // -------------------------------------------------------------------------

    /// Binding box mínimo con una variable de objeto, una de evento y un
    /// filtro O2E — representa el patrón de q1 del ejemplo.
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

    /// Binding box con los tres tipos de filtro estructural (O2E, O2O, TBE).
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

    /// QID válido para el ejemplo: protege `ObjectVariable(0)` (vehicle),
    /// lee el atributo `customer_segment` de `EventVariable(0)` (shipment).
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

    /// QID mínimo que protege un evento (para cubrir la rama Event de
    /// ProtectedVar/SourceVar).
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

    /// Política completa del ejemplo del paper (k=2, l=2, t=1.0).
    fn example_policy() -> AnonPolicy {
        // q2: protege vehicle, lee Id del departure
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

    /// Un binding box con los tres tipos de filtro estructural debe producir
    /// un Pattern con exactamente esos filtros.
    #[test]
    fn pattern_try_from_box_structural_filters_ok() {
        let bbox = bbox_all_structural();
        let result = Pattern::try_from_box(&bbox);
        assert!(result.is_ok(), "Expected Ok, got: {:?}", result);
        let pat = result.unwrap();
        assert_eq!(pat.filters.len(), 3);
    }

    /// Un binding box con un filtro no estructural debe ser rechazado.
    /// Usamos `Filter::NotEqual` como ejemplo de filtro no perteneciente a BASIC_L.
    #[test]
    fn pattern_try_from_box_non_structural_filter_err() {
        let mut bbox = bbox_o2e();
        // Añadimos un filtro no estructural: NotEqual entre dos variables de objeto
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

    /// Un binding box completamente vacío (sin variables ni filtros) debe
    /// producir un Pattern vacío sin error.
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

    /// `try_from_box` debe copiar fielmente `new_event_vars` y `new_object_vars`.
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

    /// `all_event_vars` debe devolver exactamente las claves de `event_vars`.
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

    /// `all_object_vars` debe devolver exactamente las claves de `object_vars`.
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

    /// Un QID con protected y source correctamente declarados en el patrón
    /// debe validar sin error.
    #[test]
    fn qid_validate_ok() {
        assert!(valid_qid_q1().validate().is_ok());
    }

    /// Un QID donde la variable protegida (objeto) no está en el patrón debe
    /// devolver Err con un mensaje que mencione la variable y el QID.
    #[test]
    fn qid_validate_err_protected_object_missing() {
        let mut qid = valid_qid_q1();
        qid.protected_var = ProtectedVar::Object(ObjectVariable(99)); // no declarada
        let err = qid.validate().unwrap_err();
        assert!(
            err.contains("protected object variable"),
            "Error should mention 'protected object variable'; got: {err}"
        );
        assert!(err.contains("q1"), "Error should mention QID id; got: {err}");
    }

    /// Un QID donde la variable protegida (evento) no está en el patrón debe
    /// devolver Err.
    #[test]
    fn qid_validate_err_protected_event_missing() {
        let mut qid = valid_qid_event_protected();
        qid.protected_var = ProtectedVar::Event(EventVariable(99));
        let err = qid.validate().unwrap_err();
        assert!(err.contains("protected event variable"), "{err}");
    }

    /// Un QID donde la variable fuente (evento) no está en el patrón debe
    /// devolver Err.
    #[test]
    fn qid_validate_err_source_event_missing() {
        let mut qid = valid_qid_q1();
        qid.source_var = SourceVar::Event(EventVariable(99)); // no declarada
        let err = qid.validate().unwrap_err();
        assert!(
            err.contains("source event variable"),
            "Error should mention 'source event variable'; got: {err}"
        );
    }

    /// Un QID donde la variable fuente (objeto) no está en el patrón debe
    /// devolver Err.
    #[test]
    fn qid_validate_err_source_object_missing() {
        let mut qid = valid_qid_q1();
        // Cambiamos source_var a un objeto no declarado
        qid.source_var = SourceVar::Object(ObjectVariable(99));
        let err = qid.validate().unwrap_err();
        assert!(err.contains("source object variable"), "{err}");
    }

    /// Es válido que protected_var y source_var apunten a la misma variable
    /// (un elemento se identifica a sí mismo).
    #[test]
    fn qid_validate_ok_source_equals_protected() {
        let mut qid = valid_qid_q1();
        // Hacer que source_var apunte al mismo objeto que protected_var
        qid.source_var = SourceVar::Object(ObjectVariable(0));
        qid.attribute  = QidAttribute::Id;
        assert!(qid.validate().is_ok());
    }

    // =========================================================================
    // AnonPolicy::validate
    // =========================================================================

    /// Una política sin QIDs debe devolver Err.
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

    /// Un QID inválido dentro de la política debe propagarse como Err.
    #[test]
    fn policy_validate_err_invalid_qid_propagated() {
        let mut qid = valid_qid_q1();
        qid.protected_var = ProtectedVar::Object(ObjectVariable(99)); // inválido
        let policy = AnonPolicy {
            qids:            vec![qid],
            sensitive_attrs: vec![],
            k: 2,
            l: 0,
            t: 1.0,
        };
        assert!(policy.validate().is_err());
    }

    /// Dos QIDs con τ_prot distintos deben producir Err.
    #[test]
    fn policy_validate_err_tau_prot_mismatch() {
        // q1 protege vehicle (ObjectVariable(0))
        let q1 = valid_qid_q1();

        // q_other protege shipment (EventVariable(0)) en un patrón de solo eventos
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
            protected_var: ProtectedVar::Event(EventVariable(0)), // tipo distinto
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

    /// k=1 es el valor mínimo válido.
    #[test]
    fn policy_validate_ok_k_equals_one() {
        let mut policy = example_policy();
        policy.k = 1;
        assert!(policy.validate().is_ok());
    }

    /// t > 1.0 debe ser rechazado.
    #[test]
    fn policy_validate_err_t_above_one() {
        let mut policy = example_policy();
        policy.t = 1.1;
        let err = policy.validate().unwrap_err();
        assert!(err.contains("t must be in [0, 1]"), "{err}");
    }

    /// t < 0.0 debe ser rechazado.
    #[test]
    fn policy_validate_err_t_below_zero() {
        let mut policy = example_policy();
        policy.t = -0.1;
        let err = policy.validate().unwrap_err();
        assert!(err.contains("t must be in [0, 1]"), "{err}");
    }

    /// La política completa del ejemplo (k=2, l=2, t=1.0) debe validar sin
    /// error y con los parámetros correctos.
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

    /// `protected_types_of` para un QID con variable protegida de tipo objeto
    /// debe devolver el conjunto de tipos de ese objeto.
    #[test]
    fn protected_types_of_object_var() {
        let policy = example_policy();
        let types = policy.protected_types_of(&policy.qids[0]);
        assert_eq!(types, ["vehicle".to_string()].into());
    }

    /// `protected_types_of` para un QID con variable protegida de tipo evento
    /// debe devolver el conjunto de tipos de ese evento.
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

    /// `protected_type_set` debe devolver el mismo conjunto que
    /// `protected_types_of` aplicado al primer QID.
    #[test]
    fn protected_type_set_matches_first_qid() {
        let policy = example_policy();
        let from_set  = policy.protected_type_set();
        let from_first = policy.protected_types_of(&policy.qids[0]);
        assert_eq!(from_set, from_first);
    }

    /// `protected_type_set` en una política sin QIDs (construida directamente,
    /// sin pasar por `validate`) debe devolver un conjunto vacío sin entrar en
    /// pánico.
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
