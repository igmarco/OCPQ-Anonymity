//! Test suite for the `kanon` module.
//!
//! Each submodule covers one source file:
//!
//! | File                  | Tests | Coverage                                        |
//! |-----------------------|-------|-------------------------------------------------|
//! | [`test_policy`]       |  23   | Pattern, QuasiIdentifier, AnonPolicy            |
//! | [`test_activation`]   |  25   | predicates_compatible, find_matchings, active_  |
//! | [`test_fingerprint`]  |  15   | QidValue, source_set_to_marginal, element_id    |
//! | [`test_properties`]   |  22   | eval_k/l/t, find_k/l/t, risk analysis, emd      |
//!
//! Run the full suite:
//! ```text
//! cargo test -p ocpq-shared kanon::tests
//! ```
//!
//! Run a single submodule:
//! ```text
//! cargo test -p ocpq-shared kanon::tests::test_policy
//! ```

#[cfg(test)] pub mod test_policy;
#[cfg(test)] pub mod test_activation;
#[cfg(test)] pub mod test_fingerprint;
#[cfg(test)] pub mod test_properties;