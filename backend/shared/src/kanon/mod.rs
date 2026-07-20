//! # Anonymity Framework for OCPQ (`kanon`)
//!
//! This module implements the anonymity framework described in the companion
//! paper *"k-Anonymity in OCPQ"*, adapted to the OCPQ binding-box model.
//! It provides:
//!
//! - **[`policy`]** — [`Pattern`], [`QuasiIdentifier`] and [`AnonPolicy`].
//! - **[`activation`]** — predicate compatibility, [`Matching`] search and
//!   active-binding-set construction.
//! - **[`fingerprint`]** — source-set computation, marginal fingerprints and
//!   the full [`Fingerprint`] tuple.
//! - **[`properties`]** — evaluation of k-anonymity, l-diversity and
//!   t-closeness against a computed fingerprint partition.
//! - **[`report`]** — [`AnonReport`] and [`EquivClass`], the structured output
//!   of a policy evaluation run.
//!
//! ## Scope and assumptions
//!
//! The protoype operates on a single, flat [`BindingBox`] whose output has
//! already been evaluated by the OCPQ engine.  The following restrictions
//! apply; violating them causes a [`debug_assert`] failure at runtime:
//!
//! - The [`BindingBox`] must have **no [`Constraint`]s** and **no labels**.
//!   Extending the framework to structural constraints would require checking
//!   anonymity over every sign-assignment subset (satisfied / violated for each
//!   constraint); this is documented in `properties.rs` but not implemented.
//! - Only the three structural filter kinds — `O2E`, `O2O` and
//!   `TimeBetweenEvents` — may appear in a [`Pattern`].  Other filter kinds
//!   (`NotEqual`, attribute-value filters, CEL expressions) are not part of
//!   `BASIC_L` as used here.
//! - A single qualifier is represented as `Option<String>` (`None` = wildcard).
//!   Set-valued qualifier parameters from the theoretical presentation are left
//!   as future work.
//! - All attribute values are compared with discrete equality.  Continuous
//!   attributes (e.g. timestamps with millisecond resolution) will therefore
//!   produce very fine-grained equivalence classes; binning / rounding is
//!   documented as future work.
//! - t-closeness uses the discrete ground metric only.

pub mod activation;
pub mod fingerprint;
pub mod policy;
pub mod properties;
pub mod report;
#[cfg(test)] pub mod tests;

// Convenient top-level re-exports so callers need not navigate sub-modules.
pub use activation::{find_matchings, Matching};
pub use fingerprint::{compute_fingerprints, Fingerprint, MarginalFingerprint, QidValue};
pub use policy::{AnonPolicy, QidAttribute, QuasiIdentifier};
pub use properties::{
    build_context, elements_at_risk, eval_k, eval_l, eval_t,
    find_k_max, find_l_max, find_t_min, sensitive_values_at_risk,
    KResult, LResult, TResult, PolicyContext,
};
pub use report::{check_policy, AnonReport, EquivClass, SensitiveAttrRisk};
