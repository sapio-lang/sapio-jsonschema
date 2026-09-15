# Rust-bitcoin schema integrations

This fork starts at upstream Schemars 1.2.2 and keeps the `schemars` and
`schemars_derive` package names. Patch both packages to the same reviewed fork
revision in the root Cargo workspace, then enable the integrations you need:

```toml
[dependencies]
schemars = { version = "=1.2.2", features = ["bitcoin032", "miniscript13"] }
```

Sapio's root manifest contains the complete, pinned patch table, including its
Bitcoin and Miniscript sources. External plugin workspaces must copy that table;
Cargo does not inherit patches from library dependencies. This gives all callers
one `JsonSchema` trait and one set of Bitcoin types. No Bitcoin library needs to
depend on a schema generator.

## Optional features

`bitcoin032` implements schemas for Bitcoin 0.32's amounts, addresses, public
keys, extended public keys, x-only keys, Schnorr signatures, hashes, networks,
outpoints, scripts, witnesses, transaction fields, and complete transactions.
It uses Bitcoin's hash and secp256k1 reexports to keep their type identities
aligned. `miniscript13` enables `bitcoin032` and describes concrete and semantic
policies, descriptors, and typed Miniscripts as their serialized strings.
Generic keys and script contexts do not require `JsonSchema` implementations.
Both integrations support builds without Schemars' `std` or `derive` features,
and neither is enabled by default.

The schemas describe human-readable Serde representations. Amounts use integer
satoshis over the full `u64` domain. Transaction
versions, sequences and locktimes retain their full integer domains. Scripts and
hashes use hexadecimal strings; witnesses use arrays of hexadecimal strings;
outpoints use `txid:vout`. Amount adapters that serialize BTC still need an
explicit schema for that alternate representation. `SignedAmount` has no default
Serde representation; its adapter must select the units and the matching schema.

These schemas validate JSON shapes and encodings. Bitcoin and Miniscript parsers
still validate keys, checksums, policy syntax and script typing. Applications
still select address networks and enforce monetary or consensus constraints.
The schema for `Schema` itself likewise describes its object-or-boolean Serde
representation; a host accepting untrusted schemas must separately validate
their meaning and bound the work required to evaluate them.

## Schema dialect

The upstream generator defaults to JSON Schema 2020-12. Sapio's plugin API
explicitly requests Draft 7 for both argument and return schemas, preserving the
dialect understood by its host validation and complexity limits:

```rust
use schemars::generate::SchemaSettings;

let schema = SchemaSettings::draft07()
    .into_generator()
    .into_root_schema_for::<bitcoin::Transaction>();
```

## Verification

`SchemaGenerator::subschema_for_with_contract` generates an input or output
subschema in the current reference graph, restoring the previous contract
afterward. It preserves shared definitions and recursive-type tracking across
both directions. Sapio uses it for callable interfaces nested in Rust DTOs.

```sh
cargo test -p schemars --locked --features bitcoin032,miniscript13 \
  --test bitcoin032 --test miniscript13 --test schema_value
cargo check -p schemars --locked --no-default-features \
  --features bitcoin032,miniscript13 --lib --target wasm32-unknown-unknown
cargo test --workspace --locked --all-features
```

The integration tests compare schemas with actual Serde values under both
serialization and deserialization contracts and both schema dialects. They
cover integer boundaries, transaction composition, key/hash formats, generic
Miniscript keys without schemas, and rejected JSON shapes. Sapio also exercises
the generated schemas through its plugin host and complete WASM example catalog.

The WASM check needs Clang with a wasm32 backend for secp256k1's C sources.
On macOS, set `CC_wasm32_unknown_unknown` to the installed LLVM Clang path.
