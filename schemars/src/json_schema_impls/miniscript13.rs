//! Miniscript's policies, descriptors and scripts serialize as text.
//!
//! These schemas describe the JSON representation, not the Miniscript grammar.
//! Key parsing, descriptor checksums, script typing and policy validation remain
//! the responsibility of Miniscript. Generic keys and script contexts therefore
//! do not need their own `JsonSchema` implementations.

use alloc::string::String;
use miniscript13::{policy, Descriptor, Miniscript, MiniscriptKey, ScriptContext};

forward_impl!((<Pk: MiniscriptKey> crate::JsonSchema for policy::concrete::Policy<Pk>) => String);
forward_impl!((<Pk: MiniscriptKey> crate::JsonSchema for policy::semantic::Policy<Pk>) => String);
forward_impl!((<Pk: MiniscriptKey> crate::JsonSchema for Descriptor<Pk>) => String);
forward_impl!((<Pk: MiniscriptKey, Ctx: ScriptContext> crate::JsonSchema for Miniscript<Pk, Ctx>) => String);
