//! Schemas for Bitcoin 0.32's human-readable serde representations.
//!
//! These describe JSON shapes, not consensus validity or cryptographic proofs.
//! Bitcoin's serde parsers validate keys, addresses and checksums. Monetary and
//! transaction fields retain their full Rust integer domains, including values
//! which would be invalid in an accepted Bitcoin transaction.

use crate::{json_schema, JsonSchema, Schema, SchemaGenerator};
use alloc::{borrow::Cow, vec::Vec};
use bitcoin032::{
    absolute, address::NetworkValidation, bip32::Xpub, hashes, secp256k1::schnorr,
    transaction::Version, Address, Amount, Network, OutPoint, PublicKey, Script, ScriptBuf,
    Sequence, Transaction, TxIn, TxOut, Witness, XOnlyPublicKey,
};

const HEX_BYTES: &str = "^([0-9a-fA-F]{2})*$";

macro_rules! scalar_schema {
    ($ty:ty, $name:literal, $id:literal, $schema:expr) => {
        impl JsonSchema for $ty {
            inline_schema!();

            fn schema_name() -> Cow<'static, str> {
                $name.into()
            }

            fn schema_id() -> Cow<'static, str> {
                $id.into()
            }

            fn json_schema(_: &mut SchemaGenerator) -> Schema {
                $schema
            }
        }
    };
}

macro_rules! hex_schema {
    ($ty:ty, $name:literal, $id:literal, $length:literal) => {
        scalar_schema!(
            $ty,
            $name,
            $id,
            json_schema!({
                "type": "string",
                "minLength": $length,
                "maxLength": $length,
                // Map schemas carry this pattern into patternProperties, so
                // it must enforce the width without the length keywords.
                "pattern": concat!("^[0-9a-fA-F]{", stringify!($length), "}$")
            })
        );
    };
}

impl<V: NetworkValidation> JsonSchema for Address<V> {
    inline_schema!();

    fn schema_name() -> Cow<'static, str> {
        "BitcoinAddress".into()
    }

    fn schema_id() -> Cow<'static, str> {
        "bitcoin::Address".into()
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        // Schema validation cannot establish which network the caller expects.
        json_schema!({ "type": "string" })
    }
}

scalar_schema!(
    PublicKey,
    "BitcoinPublicKey",
    "bitcoin::PublicKey",
    json_schema!({
        "type": "string",
        "pattern": "^([0-9a-fA-F]{66}|[0-9a-fA-F]{130})$"
    })
);
hex_schema!(
    XOnlyPublicKey,
    "BitcoinXOnlyPublicKey",
    "bitcoin::XOnlyPublicKey",
    64
);
hex_schema!(
    schnorr::Signature,
    "BitcoinSchnorrSignature",
    "bitcoin::secp256k1::schnorr::Signature",
    128
);
scalar_schema!(
    Xpub,
    "BitcoinXpub",
    "bitcoin::bip32::Xpub",
    json_schema!({ "type": "string" })
);

hex_schema!(
    hashes::sha256::Hash,
    "BitcoinSha256",
    "bitcoin::hashes::sha256::Hash",
    64
);
hex_schema!(
    hashes::sha256d::Hash,
    "BitcoinSha256d",
    "bitcoin::hashes::sha256d::Hash",
    64
);
hex_schema!(
    hashes::sha512::Hash,
    "BitcoinSha512",
    "bitcoin::hashes::sha512::Hash",
    128
);
hex_schema!(
    hashes::sha1::Hash,
    "BitcoinSha1",
    "bitcoin::hashes::sha1::Hash",
    40
);
hex_schema!(
    hashes::ripemd160::Hash,
    "BitcoinRipemd160",
    "bitcoin::hashes::ripemd160::Hash",
    40
);
hex_schema!(
    hashes::hash160::Hash,
    "BitcoinHash160",
    "bitcoin::hashes::hash160::Hash",
    40
);
hex_schema!(bitcoin032::Txid, "BitcoinTxid", "bitcoin::Txid", 64);
hex_schema!(bitcoin032::Wtxid, "BitcoinWtxid", "bitcoin::Wtxid", 64);
hex_schema!(
    bitcoin032::BlockHash,
    "BitcoinBlockHash",
    "bitcoin::BlockHash",
    64
);
hex_schema!(
    bitcoin032::PubkeyHash,
    "BitcoinPubkeyHash",
    "bitcoin::PubkeyHash",
    40
);
hex_schema!(
    bitcoin032::ScriptHash,
    "BitcoinScriptHash",
    "bitcoin::ScriptHash",
    40
);
hex_schema!(
    bitcoin032::WPubkeyHash,
    "BitcoinWPubkeyHash",
    "bitcoin::WPubkeyHash",
    40
);
hex_schema!(
    bitcoin032::WScriptHash,
    "BitcoinWScriptHash",
    "bitcoin::WScriptHash",
    64
);
hex_schema!(
    bitcoin032::TxMerkleNode,
    "BitcoinTxMerkleNode",
    "bitcoin::TxMerkleNode",
    64
);
hex_schema!(
    bitcoin032::WitnessMerkleNode,
    "BitcoinWitnessMerkleNode",
    "bitcoin::WitnessMerkleNode",
    64
);
hex_schema!(
    bitcoin032::WitnessCommitment,
    "BitcoinWitnessCommitment",
    "bitcoin::WitnessCommitment",
    64
);
hex_schema!(
    bitcoin032::taproot::TapLeafHash,
    "BitcoinTapLeafHash",
    "bitcoin::taproot::TapLeafHash",
    64
);
hex_schema!(
    bitcoin032::taproot::TapNodeHash,
    "BitcoinTapNodeHash",
    "bitcoin::taproot::TapNodeHash",
    64
);
hex_schema!(
    bitcoin032::taproot::TapTweakHash,
    "BitcoinTapTweakHash",
    "bitcoin::taproot::TapTweakHash",
    64
);
hex_schema!(
    bitcoin032::sighash::TapSighash,
    "BitcoinTapSighash",
    "bitcoin::sighash::TapSighash",
    64
);
hex_schema!(
    bitcoin032::sighash::LegacySighash,
    "BitcoinLegacySighash",
    "bitcoin::sighash::LegacySighash",
    64
);
hex_schema!(
    bitcoin032::sighash::SegwitV0Sighash,
    "BitcoinSegwitV0Sighash",
    "bitcoin::sighash::SegwitV0Sighash",
    64
);

scalar_schema!(
    Network,
    "BitcoinNetwork",
    "bitcoin::Network",
    json_schema!({
        "type": "string",
        "enum": ["bitcoin", "testnet", "testnet4", "signet", "regtest"]
    })
);
scalar_schema!(
    OutPoint,
    "BitcoinOutPoint",
    "bitcoin::OutPoint",
    json_schema!({
        "type": "string",
        "pattern": "^[0-9a-fA-F]{64}:(0|[1-9][0-9]{0,9})$"
    })
);
scalar_schema!(
    Amount,
    "BitcoinAmount",
    "bitcoin::Amount",
    json_schema!({
        "type": "integer", "minimum": 0, "maximum": u64::MAX
    })
);
scalar_schema!(
    Version,
    "BitcoinTransactionVersion",
    "bitcoin::transaction::Version",
    json_schema!({
        "type": "integer", "minimum": i32::MIN, "maximum": i32::MAX
    })
);
scalar_schema!(
    Sequence,
    "BitcoinSequence",
    "bitcoin::Sequence",
    json_schema!({
        "type": "integer", "minimum": 0, "maximum": u32::MAX
    })
);
scalar_schema!(
    absolute::LockTime,
    "BitcoinAbsoluteLockTime",
    "bitcoin::absolute::LockTime",
    json_schema!({
        "type": "integer", "minimum": 0, "maximum": u32::MAX
    })
);
scalar_schema!(
    Script,
    "BitcoinScript",
    "bitcoin::Script",
    json_schema!({
        "type": "string", "pattern": HEX_BYTES
    })
);
forward_impl!(ScriptBuf => Script);
scalar_schema!(
    Witness,
    "BitcoinWitness",
    "bitcoin::Witness",
    json_schema!({
        "type": "array", "items": { "type": "string", "pattern": HEX_BYTES }
    })
);

impl JsonSchema for TxIn {
    fn schema_name() -> Cow<'static, str> {
        "BitcoinTxIn".into()
    }

    fn schema_id() -> Cow<'static, str> {
        "bitcoin::TxIn".into()
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "object",
            "required": ["previous_output", "script_sig", "sequence", "witness"],
            "properties": {
                "previous_output": generator.subschema_for::<OutPoint>(),
                "script_sig": generator.subschema_for::<ScriptBuf>(),
                "sequence": generator.subschema_for::<Sequence>(),
                "witness": generator.subschema_for::<Witness>()
            }
        })
    }
}

impl JsonSchema for TxOut {
    fn schema_name() -> Cow<'static, str> {
        "BitcoinTxOut".into()
    }

    fn schema_id() -> Cow<'static, str> {
        "bitcoin::TxOut".into()
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "object",
            "required": ["value", "script_pubkey"],
            "properties": {
                "value": generator.subschema_for::<Amount>(),
                "script_pubkey": generator.subschema_for::<ScriptBuf>()
            }
        })
    }
}

impl JsonSchema for Transaction {
    fn schema_name() -> Cow<'static, str> {
        "BitcoinTransaction".into()
    }

    fn schema_id() -> Cow<'static, str> {
        "bitcoin::Transaction".into()
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "object",
            "required": ["version", "lock_time", "input", "output"],
            "properties": {
                "version": generator.subschema_for::<Version>(),
                "lock_time": generator.subschema_for::<absolute::LockTime>(),
                "input": generator.subschema_for::<Vec<TxIn>>(),
                "output": generator.subschema_for::<Vec<TxOut>>()
            }
        })
    }
}
