//! Anonymity-policy data types (Definitions 1-4, §4.1).
//!
//! | Paper concept              | Rust type                       |
//! |-----------------------------|----------------------------------|
//! | Pattern (Def. 1)            | [`Pattern`]                     |
//! | Quasi-identifier (Def. 2)   | [`QuasiIdentifier`]             |
//! | Sensitive attr. set (Def. 3)| `Vec<String>` in [`AnonPolicy`] |
//! | Anonymity policy (Def. 4)   | [`AnonPolicy`]                  |
//!
//! A [`Pattern`] is a [`BindingBox`] restricted to `BASIC_L`
//! ([`Filter::O2E`], [`Filter::O2O`], [`Filter::TimeBetweenEvents`]),
//! enforced by [`Pattern::try_from_box`].

use std::collections::{HashMap, HashSet};

use crate::binding_box::structs::{
    BindingBox, EventVariable, Filter, ObjectVariable,
};

// ---------------------------------------------------------------------------
// Pattern
// ---------------------------------------------------------------------------

/// A binding box restricted to `BASIC_L` predicates (Definition 1).
#[derive(Debug, Clone)]
pub struct Pattern {
    /// Declared event variables and admissible types.
    pub event_vars: HashMap<EventVariable, HashSet<String>>,
    /// Declared object variables and admissible types.
    pub object_vars: HashMap<ObjectVariable, HashSet<String>>,
    /// Structural predicates only (`O2E`, `O2O`, `TimeBetweenEvents`).
    pub filters: Vec<Filter>,
}

impl Pattern {
    /// Builds a [`Pattern`] from `bbox`; errors on non-structural filters.
    pub fn try_from_box(bbox: &BindingBox) -> Result<Self, String> {
        for f in &bbox.filters {
            match f {
                Filter::O2E { .. } | Filter::O2O { .. } | Filter::TimeBetweenEvents { .. } => {}
                other => {
                    return Err(format!(
                        "Pattern may only contain O2E, O2O or TimeBetweenEvents filters; \
                         found: {other:?}"
                    ));
                }
            }
        }
        Ok(Self {
            event_vars: bbox.new_event_vars.clone(),
            object_vars: bbox.new_object_vars.clone(),
            filters: bbox.filters.clone(),
        })
    }

    /// Event variables declared by this pattern.
    pub fn all_event_vars(&self) -> impl Iterator<Item = EventVariable> + '_ {
        self.event_vars.keys().copied()
    }

    /// Object variables declared by this pattern.
    pub fn all_object_vars(&self) -> impl Iterator<Item = ObjectVariable> + '_ {
        self.object_vars.keys().copied()
    }
}

// ---------------------------------------------------------------------------
// QidAttribute
// ---------------------------------------------------------------------------

/// The attribute `a_q` read from a QID's source variable (Def. 2), including
/// the `id`/`time` special cases ("Identifiers and timestamps as QIDs").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QidAttribute {
    /// `aval(x, "id") = x`.
    Id,
    /// Event timestamp (millisecond resolution; no binning, see module docs).
    /// Meaningless for object source variables.
    Timestamp,
    /// A named OCED attribute.
    Named(String),
}

// ---------------------------------------------------------------------------
// QuasiIdentifier
// ---------------------------------------------------------------------------

/// A quasi-identifier: pattern + protected variable + source variable +
/// attribute (Definition 2).
#[derive(Debug, Clone)]
pub struct QuasiIdentifier {
    /// Human-readable ID, used in reports.
    pub id: String,
    /// The pattern `p_q`.
    pub pattern: Pattern,
    /// The protected variable `v_prot^q`; must be declared in `pattern`.
    pub protected_var: ProtectedVar,
    /// The source variable `v_q`; must be declared in `pattern`.
    pub source_var: SourceVar,
    /// The QID attribute `a_q`.
    pub attribute: QidAttribute,
}

/// The protected variable of a QID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtectedVar {
    /// `v_prot^q` is an event variable.
    Event(EventVariable),
    /// `v_prot^q` is an object variable.
    Object(ObjectVariable),
}

/// The source variable of a QID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceVar {
    /// `v_q` is an event variable.
    Event(EventVariable),
    /// `v_q` is an object variable.
    Object(ObjectVariable),
}

impl QuasiIdentifier {
    /// Checks that `protected_var` and `source_var` are declared in `pattern`.
    pub fn validate(&self) -> Result<(), String> {
        // Check protected var
        match &self.protected_var {
            ProtectedVar::Event(ev) => {
                if !self.pattern.event_vars.contains_key(ev) {
                    return Err(format!(
                        "QID '{}': protected event variable {ev:?} not declared in pattern",
                        self.id
                    ));
                }
            }
            ProtectedVar::Object(ov) => {
                if !self.pattern.object_vars.contains_key(ov) {
                    return Err(format!(
                        "QID '{}': protected object variable {ov:?} not declared in pattern",
                        self.id
                    ));
                }
            }
        }
        // Check source var
        match &self.source_var {
            SourceVar::Event(ev) => {
                if !self.pattern.event_vars.contains_key(ev) {
                    return Err(format!(
                        "QID '{}': source event variable {ev:?} not declared in pattern",
                        self.id
                    ));
                }
            }
            SourceVar::Object(ov) => {
                if !self.pattern.object_vars.contains_key(ov) {
                    return Err(format!(
                        "QID '{}': source object variable {ov:?} not declared in pattern",
                        self.id
                    ));
                }
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// AnonPolicy
// ---------------------------------------------------------------------------

/// A finite set of QIDs, a sensitive-attribute set, and the parameters
/// k, l, t (Definition 4).
///
/// ## Invariants (checked by [`AnonPolicy::validate`])
/// - All QIDs agree on `τ_prot`.
/// - `k ≥ 1`, `l ≥ 0`, `0 ≤ t ≤ 1` (`l = 0` / `t = 1.0` ⟹ trivially satisfied).
#[derive(Debug, Clone)]
pub struct AnonPolicy {
    /// Non-empty set of QIDs.
    pub qids: Vec<QuasiIdentifier>,
    /// Sensitive attribute names (`S ⊆ U_attr`); may be empty.
    pub sensitive_attrs: Vec<String>,
    /// k-anonymity parameter.
    pub k: usize,
    /// l-diversity parameter.
    pub l: usize,
    /// t-closeness parameter.
    pub t: f64,
}

impl AnonPolicy {
    /// Checks: non-empty QIDs, each QID valid, all QIDs agree on `τ_prot`,
    /// parameter ranges.
    pub fn validate(&self) -> Result<(), String> {
        if self.qids.is_empty() {
            return Err("AnonPolicy must have at least one QID".into());
        }
        for qid in &self.qids {
            qid.validate()?;
        }
        // Check τ_prot consistency: all protected variables must admit the same
        // set of types.
        let first_prot_types = self.protected_types_of(&self.qids[0]);
        for qid in self.qids.iter().skip(1) {
            let types = self.protected_types_of(qid);
            if types != first_prot_types {
                return Err(format!(
                    "QID '{}' has protected types {types:?} but first QID has {first_prot_types:?}; \
                     all QIDs must agree on τ_prot",
                    qid.id
                ));
            }
        }
        // Parameter ranges
        if self.k < 1 {
            return Err("k must be ≥ 1".into());
        }
        if !(0.0..=1.0).contains(&self.t) {
            return Err(format!("t must be in [0, 1]; got {}", self.t));
        }
        Ok(())
    }

    /// Type names admitted for the protected variable of `qid`.
    pub fn protected_types_of(&self, qid: &QuasiIdentifier) -> HashSet<String> {
        match &qid.protected_var {
            ProtectedVar::Event(ev) => qid
                .pattern
                .event_vars
                .get(ev)
                .cloned()
                .unwrap_or_default(),
            ProtectedVar::Object(ov) => qid
                .pattern
                .object_vars
                .get(ov)
                .cloned()
                .unwrap_or_default(),
        }
    }

    /// `τ_prot` (consistent across QIDs by the invariant; read from the first).
    pub fn protected_type_set(&self) -> HashSet<String> {
        if let Some(first) = self.qids.first() {
            self.protected_types_of(first)
        } else {
            HashSet::new()
        }
    }
}