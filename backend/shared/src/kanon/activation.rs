//! Policy activation: pattern matching and active-binding-set construction.
//!
//! Implements §4.2 of the companion paper:
//!
//! | Paper concept                    | Rust item                  |
//! |------------------------------------|-----------------------------|
//! | Predicate compatibility (Def. 5)   | [`predicates_compatible`]  |
//! | Matching φ: p → b (Def. 6)         | [`Matching`] / [`find_matchings`] |
//! | Active binding set (Def. 7)        | [`active_binding_set`]     |
//! | QID/policy activation (Def. 8)     | [`qid_is_activated`]       |
//!
//! ## Qualifier representation
//!
//! The paper allows a set `Q ⊆ U_qual` per predicate; here a single qualifier
//! is `Option<String>` (`None` = wildcard `U_qual`). `None` is compatible with
//! anything; `Some(q1)`/`Some(q2)` iff `q1 == q2`. Set-valued qualifiers are
//! future work.

use std::collections::HashMap;
use std::sync::Arc;

use process_mining::core::event_data::object_centric::linked_ocel::{
    slim_linked_ocel::EventOrObjectIndex, SlimLinkedOCEL,
};

use crate::binding_box::structs::{
    Binding, BindingBox, EventVariable, Filter, ObjectVariable,
};

use crate::kanon::policy::{Pattern, ProtectedVar, QuasiIdentifier, SourceVar};

// ---------------------------------------------------------------------------
// Predicate compatibility
// ---------------------------------------------------------------------------

/// Predicate compatibility (Definition 5): same symbol, same renamed
/// variable arguments, non-empty parameter intersection. `pattern_filter`
/// must already be renamed by a candidate matching.
pub fn predicates_compatible(pattern_filter: &Filter, box_filter: &Filter) -> bool {
    match (pattern_filter, box_filter) {
        // E2O (called O2E in OCPQ, same relationship, notation differs)
        (
            Filter::O2E {
                object: po,
                event: pe,
                qualifier: pq,
                ..
            },
            Filter::O2E {
                object: bo,
                event: be,
                qualifier: bq,
                ..
            },
        ) => po == bo && pe == be && qualifiers_compatible(pq, bq),

        // O2O
        (
            Filter::O2O {
                object: po,
                other_object: po2,
                qualifier: pq,
                ..
            },
            Filter::O2O {
                object: bo,
                other_object: bo2,
                qualifier: bq,
                ..
            },
        ) => po == bo && po2 == bo2 && qualifiers_compatible(pq, bq),

        // TBE
        (
            Filter::TimeBetweenEvents {
                from_event: pf,
                to_event: pt,
                min_seconds: p_min,
                max_seconds: p_max,
            },
            Filter::TimeBetweenEvents {
                from_event: bf,
                to_event: bt,
                min_seconds: b_min,
                max_seconds: b_max,
            },
        ) => pf == bf && pt == bt && intervals_overlap(*p_min, *p_max, *b_min, *b_max),

        // Filters of different kinds are never compatible
        _ => false,
    }
}

/// `None` (wildcard) compatible with anything; else equal.
pub(crate) fn qualifiers_compatible(a: &Option<String>, b: &Option<String>) -> bool {
    match (a, b) {
        (None, _) | (_, None) => true,
        (Some(qa), Some(qb)) => qa == qb,
    }
}

/// `true` iff `[p_min, p_max] ∩ [b_min, b_max] ≠ ∅` (`None` = unbounded).
pub(crate) fn intervals_overlap(
    p_min: Option<f64>,
    p_max: Option<f64>,
    b_min: Option<f64>,
    b_max: Option<f64>,
) -> bool {
    // upper bound of intersection = min(p_max, b_max)  (None = +∞ → no bound)
    // lower bound of intersection = max(p_min, b_min)  (None = -∞ → no bound)
    // non-empty iff lower ≤ upper
    let lower = match (p_min, b_min) {
        (Some(a), Some(b)) => Some(f64::max(a, b)),
        (Some(v), None) | (None, Some(v)) => Some(v),
        (None, None) => None,
    };
    let upper = match (p_max, b_max) {
        (Some(a), Some(b)) => Some(f64::min(a, b)),
        (Some(v), None) | (None, Some(v)) => Some(v),
        (None, None) => None,
    };
    match (lower, upper) {
        (Some(lo), Some(hi)) => lo <= hi,
        _ => true, // one or both bounds are ±∞, always overlaps
    }
}

// ---------------------------------------------------------------------------
// Matching
// ---------------------------------------------------------------------------

/// An injective matching `φ : dom(Var_p) → dom(Var_b)` (Definition 6).
/// Event and object variables are renamed independently (disjoint namespaces).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Matching {
    /// Pattern event-variable → box event-variable.
    pub ev_map: HashMap<EventVariable, EventVariable>,
    /// Pattern object-variable → box object-variable.
    pub ob_map: HashMap<ObjectVariable, ObjectVariable>,
}

impl Matching {
    /// Renames the variables of a pattern filter via φ; `None` if a
    /// referenced variable is unmapped (should not happen for a well-formed φ).
    pub fn apply_to_filter(&self, f: &Filter) -> Option<Filter> {
        match f {
            Filter::O2E {
                object,
                event,
                qualifier,
                filter_label,
            } => {
                let ob = self.ob_map.get(object)?;
                let ev = self.ev_map.get(event)?;
                Some(Filter::O2E {
                    object: *ob,
                    event: *ev,
                    qualifier: qualifier.clone(),
                    filter_label: *filter_label,
                })
            }
            Filter::O2O {
                object,
                other_object,
                qualifier,
                filter_label,
            } => {
                let ob1 = self.ob_map.get(object)?;
                let ob2 = self.ob_map.get(other_object)?;
                Some(Filter::O2O {
                    object: *ob1,
                    other_object: *ob2,
                    qualifier: qualifier.clone(),
                    filter_label: *filter_label,
                })
            }
            Filter::TimeBetweenEvents {
                from_event,
                to_event,
                min_seconds,
                max_seconds,
            } => {
                let ef = self.ev_map.get(from_event)?;
                let et = self.ev_map.get(to_event)?;
                Some(Filter::TimeBetweenEvents {
                    from_event: *ef,
                    to_event: *et,
                    min_seconds: *min_seconds,
                    max_seconds: *max_seconds,
                })
            }
            _ => None, // non-structural filters not supported in patterns
        }
    }

    /// φ applied to a pattern event variable.
    pub fn apply_to_ev_var(&self, v: EventVariable) -> Option<EventVariable> {
        self.ev_map.get(&v).copied()
    }

    /// φ applied to a pattern object variable.
    pub fn apply_to_ob_var(&self, v: ObjectVariable) -> Option<ObjectVariable> {
        self.ob_map.get(&v).copied()
    }
}

// ---------------------------------------------------------------------------
// Finding all matchings (backtracking search)
// ---------------------------------------------------------------------------

/// All matchings φ of `pattern` into `bbox` (Definition 6: type + predicate
/// compatibility). Backtracking search, event/object variables enumerated
/// independently. Fast for typical patterns (2-6 variables); a pattern with
/// no predicates enumerates all injections.
pub fn find_matchings(pattern: &Pattern, bbox: &BindingBox) -> Vec<Matching> {
    let pat_ev_vars: Vec<EventVariable> = pattern.all_event_vars().collect();
    let pat_ob_vars: Vec<ObjectVariable> = pattern.all_object_vars().collect();

    let box_ev_vars: Vec<EventVariable> = bbox.new_event_vars.keys().copied().collect();
    let box_ob_vars: Vec<ObjectVariable> = bbox.new_object_vars.keys().copied().collect();

    let mut results = Vec::new();

    backtrack_ev(
        &pat_ev_vars,
        &pat_ob_vars,
        &box_ev_vars,
        &box_ob_vars,
        pattern,
        bbox,
        &mut HashMap::new(),
        &mut HashMap::new(),
        &mut results,
    );

    results
}

/// Backtracking over event variables; delegates to [`backtrack_ob`] once done.
#[allow(clippy::too_many_arguments)]
pub(crate) fn backtrack_ev(
    rem_ev: &[EventVariable],
    rem_ob: &[ObjectVariable],
    box_evs: &[EventVariable],
    box_obs: &[ObjectVariable],
    pattern: &Pattern,
    bbox: &BindingBox,
    ev_map: &mut HashMap<EventVariable, EventVariable>,
    ob_map: &mut HashMap<ObjectVariable, ObjectVariable>,
    results: &mut Vec<Matching>,
) {
    if rem_ev.is_empty() {
        backtrack_ob(rem_ob, box_obs, pattern, bbox, ev_map, ob_map, results);
        return;
    }

    let pat_var = rem_ev[0];
    let pat_types = pattern
        .event_vars
        .get(&pat_var)
        .expect("pattern variable missing from event_vars");

    // Track which box variables are already used (injectivity)
    let used: std::collections::HashSet<EventVariable> = ev_map.values().copied().collect();

    for &box_var in box_evs {
        if used.contains(&box_var) {
            continue;
        }
        // Type compatibility: intersection must be non-empty
        if let Some(box_types) = bbox.new_event_vars.get(&box_var) {
            if pat_types.is_disjoint(box_types) {
                continue;
            }
        } else {
            continue;
        }

        ev_map.insert(pat_var, box_var);

        // Early predicate check: if any pattern filter (after renaming) is
        // incompatible with all box filters, prune this branch.
        if !partial_predicate_check(pattern, bbox, ev_map, ob_map) {
            ev_map.remove(&pat_var);
            continue;
        }

        backtrack_ev(
            &rem_ev[1..],
            rem_ob,
            box_evs,
            box_obs,
            pattern,
            bbox,
            ev_map,
            ob_map,
            results,
        );

        ev_map.remove(&pat_var);
    }
}

/// Recursive backtracking over object variables.
#[allow(clippy::too_many_arguments)]
pub(crate) fn backtrack_ob(
    rem_ob: &[ObjectVariable],
    box_obs: &[ObjectVariable],
    pattern: &Pattern,
    bbox: &BindingBox,
    ev_map: &mut HashMap<EventVariable, EventVariable>,
    ob_map: &mut HashMap<ObjectVariable, ObjectVariable>,
    results: &mut Vec<Matching>,
) {
    if rem_ob.is_empty() {
        // Complete assignment: verify full predicate compatibility
        if full_predicate_check(pattern, bbox, ev_map, ob_map) {
            results.push(Matching {
                ev_map: ev_map.clone(),
                ob_map: ob_map.clone(),
            });
        }
        return;
    }

    let pat_var = rem_ob[0];
    let pat_types = pattern
        .object_vars
        .get(&pat_var)
        .expect("pattern variable missing from object_vars");

    let used: std::collections::HashSet<ObjectVariable> = ob_map.values().copied().collect();

    for &box_var in box_obs {
        if used.contains(&box_var) {
            continue;
        }
        if let Some(box_types) = bbox.new_object_vars.get(&box_var) {
            if pat_types.is_disjoint(box_types) {
                continue;
            }
        } else {
            continue;
        }

        ob_map.insert(pat_var, box_var);

        if !partial_predicate_check(pattern, bbox, ev_map, ob_map) {
            ob_map.remove(&pat_var);
            continue;
        }

        backtrack_ob(
            &rem_ob[1..],
            box_obs,
            pattern,
            bbox,
            ev_map,
            ob_map,
            results,
        );

        ob_map.remove(&pat_var);
    }
}

/// Pruning check: for each pattern filter fully assigned in the partial
/// matching, some box filter must be compatible with its renamed version.
pub(crate) fn partial_predicate_check(
    pattern: &Pattern,
    bbox: &BindingBox,
    ev_map: &HashMap<EventVariable, EventVariable>,
    ob_map: &HashMap<ObjectVariable, ObjectVariable>,
) -> bool {
    let partial = Matching {
        ev_map: ev_map.clone(),
        ob_map: ob_map.clone(),
    };
    for pf in &pattern.filters {
        if !filter_vars_assigned(pf, &partial) {
            continue; // not yet checkable
        }
        if let Some(renamed) = partial.apply_to_filter(pf) {
            if !bbox
                .filters
                .iter()
                .any(|bf| predicates_compatible(&renamed, bf))
            {
                return false;
            }
        }
    }
    true
}

/// Final check: every pattern filter has a compatible box filter
/// (all variables assigned).
pub(crate) fn full_predicate_check(
    pattern: &Pattern,
    bbox: &BindingBox,
    ev_map: &HashMap<EventVariable, EventVariable>,
    ob_map: &HashMap<ObjectVariable, ObjectVariable>,
) -> bool {
    let matching = Matching {
        ev_map: ev_map.clone(),
        ob_map: ob_map.clone(),
    };
    for pf in &pattern.filters {
        match matching.apply_to_filter(pf) {
            Some(renamed) => {
                if !bbox
                    .filters
                    .iter()
                    .any(|bf| predicates_compatible(&renamed, bf))
                {
                    return false;
                }
            }
            None => return false, // unassigned variable — should not happen here
        }
    }
    true
}

/// `true` iff every variable referenced by `f` is assigned in `m`.
pub(crate) fn filter_vars_assigned(f: &Filter, m: &Matching) -> bool {
    match f {
        Filter::O2E { object, event, .. } => {
            m.ob_map.contains_key(object) && m.ev_map.contains_key(event)
        }
        Filter::O2O {
            object,
            other_object,
            ..
        } => m.ob_map.contains_key(object) && m.ob_map.contains_key(other_object),
        Filter::TimeBetweenEvents {
            from_event,
            to_event,
            ..
        } => m.ev_map.contains_key(from_event) && m.ev_map.contains_key(to_event),
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// QID activation
// ---------------------------------------------------------------------------

/// `true` iff [`find_matchings`] is non-empty (Definition 8).
pub fn qid_is_activated(qid: &QuasiIdentifier, bbox: &BindingBox) -> bool {
    !find_matchings(&qid.pattern, bbox).is_empty()
}

// ---------------------------------------------------------------------------
// Active binding set construction
// ---------------------------------------------------------------------------

/// `Act(q, b, φ)` (Definition 7): bindings of `out` satisfying `b_φ ⊨ p_q`,
/// checked via renamed pattern filters against OCPQ's `Filter::check_binding`.
///
/// # Panics
/// Panics if a pattern filter fails to rename (invalid `phi`).
pub fn active_binding_set<'a>(
    qid: &QuasiIdentifier,
    phi: &Matching,
    out: &'a [Arc<Binding>],
    ocel: &'a SlimLinkedOCEL,
) -> Vec<&'a Arc<Binding>> {
    let renamed_filters: Vec<Filter> = qid
        .pattern
        .filters
        .iter()
        .map(|f| {
            phi.apply_to_filter(f)
                .expect("active_binding_set: filter references variable not in matching")
        })
        .collect();

    out.iter()
        .filter(|b: &&Arc<Binding>| {
            renamed_filters
                .iter()
                .all(|f: &Filter| f.check_binding(b, ocel).unwrap_or(false))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Protected-element index resolution
// ---------------------------------------------------------------------------

/// The [`EventOrObjectIndex`] bound to `φ(v_prot)` in `binding`, or `None`
/// if absent.
pub fn protected_index_in_binding(
    qid: &QuasiIdentifier,
    phi: &Matching,
    binding: &Binding,
) -> Option<EventOrObjectIndex> {
    match &qid.protected_var {
        ProtectedVar::Event(pat_ev) => {
            let box_ev = phi.apply_to_ev_var(*pat_ev)?;
            binding
                .get_ev_index(&box_ev)
                .map(|ei| EventOrObjectIndex::Event(*ei))
        }
        ProtectedVar::Object(pat_ob) => {
            let box_ob = phi.apply_to_ob_var(*pat_ob)?;
            binding
                .get_ob_index(&box_ob)
                .map(|oi| EventOrObjectIndex::Object(*oi))
        }
    }
}

/// The [`EventOrObjectIndex`] bound to `φ(v_q)` in `binding`, or `None` if absent.
pub fn source_index_in_binding(
    qid: &QuasiIdentifier,
    phi: &Matching,
    binding: &Binding,
) -> Option<EventOrObjectIndex> {
    match &qid.source_var {
        SourceVar::Event(pat_ev) => {
            let box_ev = phi.apply_to_ev_var(*pat_ev)?;
            binding
                .get_ev_index(&box_ev)
                .map(|ei| EventOrObjectIndex::Event(*ei))
        }
        SourceVar::Object(pat_ob) => {
            let box_ob = phi.apply_to_ob_var(*pat_ob)?;
            binding
                .get_ob_index(&box_ob)
                .map(|oi| EventOrObjectIndex::Object(*oi))
        }
    }
}