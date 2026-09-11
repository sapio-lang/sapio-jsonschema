#![cfg(feature = "bitcoin032")]

use bitcoin032::{
    absolute,
    address::NetworkUnchecked,
    bip32::{Xpriv, Xpub},
    hashes::{self, Hash},
    secp256k1::{self, Keypair, Message, Secp256k1, SecretKey},
    transaction::Version,
    Address, Amount, Network, OutPoint, PublicKey, Script, ScriptBuf, Sequence, Transaction, TxIn,
    TxOut, Txid, Witness, XOnlyPublicKey,
};
use schemars::{
    generate::{Contract, SchemaSettings},
    JsonSchema, Schema,
};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;

fn schemas<T: ?Sized + JsonSchema>() -> Vec<Schema> {
    [SchemaSettings::default(), SchemaSettings::draft07()]
        .into_iter()
        .flat_map(|settings| {
            [Contract::Serialize, Contract::Deserialize].map(|contract| {
                settings
                    .clone()
                    .with(|settings| settings.contract = contract)
                    .into_generator()
                    .into_root_schema_for::<T>()
            })
        })
        .collect()
}

fn assert_accepts<T: ?Sized + JsonSchema + Serialize>(value: &T) -> Value {
    let value = serde_json::to_value(value).unwrap();
    for schema in schemas::<T>() {
        let validator = jsonschema::validator_for(schema.as_value()).unwrap();
        assert!(
            validator.is_valid(&value),
            "{} rejected {value}",
            schema.as_value()
        );
    }
    value
}

fn assert_rejects<T: ?Sized + JsonSchema>(values: impl IntoIterator<Item = Value>) {
    let validators: Vec<_> = schemas::<T>()
        .iter()
        .map(|schema| jsonschema::validator_for(schema.as_value()).unwrap())
        .collect();
    for value in values {
        assert!(
            validators
                .iter()
                .all(|validator| !validator.is_valid(&value)),
            "accepted {value}"
        );
    }
}

fn keypair() -> Keypair {
    Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[1; 32]).unwrap())
}

#[test]
fn address_validation_markers_and_networks_share_the_actual_string_shape() {
    let secp = Secp256k1::new();
    let key = keypair();
    let (xonly, _) = key.x_only_public_key();
    let public = PublicKey::new(key.public_key());
    assert_eq!(
        <Address>::schema_id(),
        Address::<NetworkUnchecked>::schema_id()
    );
    assert_eq!(schemas::<Address>(), schemas::<Address<NetworkUnchecked>>());
    for network in [
        Network::Bitcoin,
        Network::Testnet,
        Network::Testnet4,
        Network::Signet,
        Network::Regtest,
    ] {
        for address in [
            Address::p2tr(&secp, xonly, None, network),
            Address::p2pkh(public, network),
        ] {
            let encoded = assert_accepts(&address);
            assert!(encoded.is_string());
            let unchecked: Address<NetworkUnchecked> =
                serde_json::from_value(encoded.clone()).unwrap();
            assert_eq!(assert_accepts(&unchecked), encoded);
            assert_eq!(unchecked.require_network(network).unwrap(), address);
        }
    }
    assert_rejects::<Address>([json!(null), json!({"address": "bc1"}), json!(7)]);
}

#[test]
fn keys_and_signatures_match_hex_and_extended_keys_match_base58() {
    let secp = Secp256k1::new();
    let key = keypair();
    let (xonly, _) = key.x_only_public_key();
    for public in [
        PublicKey::new(key.public_key()),
        PublicKey::new_uncompressed(key.public_key()),
    ] {
        let encoded = assert_accepts(&public);
        assert_eq!(
            serde_json::from_value::<PublicKey>(encoded).unwrap(),
            public
        );
    }
    assert_eq!(assert_accepts(&xonly), json!(xonly.to_string()));
    let signature = secp.sign_schnorr_no_aux_rand(&Message::from_digest([2; 32]), &key);
    let encoded = assert_accepts(&signature);
    assert_eq!(
        serde_json::from_value::<secp256k1::schnorr::Signature>(encoded).unwrap(),
        signature
    );
    for network in [Network::Bitcoin, Network::Regtest] {
        let root = Xpub::from_priv(&secp, &Xpriv::new_master(network, &[3; 32]).unwrap());
        assert_eq!(assert_accepts(&root), json!(root.to_string()));
    }
    assert_rejects::<PublicKey>([json!("00"), json!("g".repeat(66)), json!(vec![0; 33])]);
    assert_rejects::<XOnlyPublicKey>([json!("00"), json!("f".repeat(63)), json!(7)]);
    assert_rejects::<secp256k1::schnorr::Signature>([
        json!("f".repeat(126)),
        json!("z".repeat(128)),
    ]);
    assert_rejects::<Xpub>([json!(null), json!({"public_key": xonly.to_string()})]);

    // A shape-valid point still needs Bitcoin's cryptographic parser.
    let invalid_point = json!("00".repeat(32));
    assert!(
        jsonschema::validator_for(schemas::<XOnlyPublicKey>()[0].as_value())
            .unwrap()
            .is_valid(&invalid_point)
    );
    assert!(serde_json::from_value::<XOnlyPublicKey>(invalid_point).is_err());
}

#[test]
fn bitcoin_map_keys_enforce_hex_width_in_both_schema_dialects() {
    fn check<K: Ord + JsonSchema + Serialize + serde::de::DeserializeOwned>(key: K) {
        let map = BTreeMap::from([(key, 1u8)]);
        let encoded = assert_accepts(&map);
        assert!(serde_json::from_value::<BTreeMap<K, u8>>(encoded).is_ok());

        for key in [
            "a".to_owned(),
            "a".repeat(63),
            "a".repeat(65),
            "g".repeat(64),
        ] {
            let invalid = Value::Object(serde_json::Map::from_iter([(key, json!(1))]));
            assert!(serde_json::from_value::<BTreeMap<K, u8>>(invalid.clone()).is_err());
            assert_rejects::<BTreeMap<K, u8>>([invalid]);
        }
    }

    check(keypair().x_only_public_key().0);
    check(hashes::sha256::Hash::from_byte_array([1; 32]));
}

#[test]
fn common_bitcoin_hashes_keep_their_human_readable_encodings() {
    macro_rules! check_hash {
        ($ty:ty, $bytes:expr) => {{
            let hash = <$ty>::from_byte_array($bytes);
            let encoded = assert_accepts(&hash);
            assert_eq!(encoded, json!(hash.to_string()));
            assert_eq!(serde_json::from_value::<$ty>(encoded).unwrap(), hash);
            assert_rejects::<$ty>([json!(""), json!("zz"), json!([0, 1])]);
        }};
    }
    check_hash!(hashes::sha256::Hash, [1; 32]);
    check_hash!(hashes::sha256d::Hash, [2; 32]);
    check_hash!(hashes::sha512::Hash, [3; 64]);
    check_hash!(hashes::sha1::Hash, [4; 20]);
    check_hash!(hashes::ripemd160::Hash, [5; 20]);
    check_hash!(hashes::hash160::Hash, [6; 20]);
    check_hash!(bitcoin032::Txid, [7; 32]);
    check_hash!(bitcoin032::Wtxid, [8; 32]);
    check_hash!(bitcoin032::BlockHash, [9; 32]);
    check_hash!(bitcoin032::PubkeyHash, [10; 20]);
    check_hash!(bitcoin032::ScriptHash, [11; 20]);
    check_hash!(bitcoin032::WPubkeyHash, [12; 20]);
    check_hash!(bitcoin032::WScriptHash, [13; 32]);
    check_hash!(bitcoin032::TxMerkleNode, [14; 32]);
    check_hash!(bitcoin032::WitnessMerkleNode, [15; 32]);
    check_hash!(bitcoin032::WitnessCommitment, [16; 32]);
    check_hash!(bitcoin032::taproot::TapLeafHash, [17; 32]);
    check_hash!(bitcoin032::taproot::TapNodeHash, [18; 32]);
    check_hash!(bitcoin032::taproot::TapTweakHash, [19; 32]);
    check_hash!(bitcoin032::sighash::TapSighash, [20; 32]);
    check_hash!(bitcoin032::sighash::LegacySighash, [21; 32]);
    check_hash!(bitcoin032::sighash::SegwitV0Sighash, [22; 32]);
}

#[test]
fn network_uses_the_default_serde_names() {
    for (network, text) in [
        (Network::Bitcoin, "bitcoin"),
        (Network::Testnet, "testnet"),
        (Network::Testnet4, "testnet4"),
        (Network::Signet, "signet"),
        (Network::Regtest, "regtest"),
    ] {
        assert_eq!(assert_accepts(&network), json!(text));
    }
    assert_rejects::<Network>([json!("Bitcoin"), json!("main"), json!("test"), json!(4)]);
}

#[test]
fn monetary_and_transaction_fields_keep_the_full_integer_domains() {
    for sats in [
        0,
        1,
        Amount::MAX_MONEY.to_sat(),
        Amount::MAX_MONEY.to_sat() + 1,
        u64::MAX,
    ] {
        let amount = Amount::from_sat(sats);
        assert_eq!(assert_accepts(&amount), json!(sats));
        assert_eq!(
            serde_json::from_value::<Amount>(json!(sats)).unwrap(),
            amount
        );
    }
    for value in [0, 1, 499_999_999, 500_000_000, u32::MAX] {
        assert_eq!(assert_accepts(&Sequence(value)), json!(value));
        assert_eq!(
            assert_accepts(&absolute::LockTime::from_consensus(value)),
            json!(value)
        );
    }
    for value in [i32::MIN, -1, 0, 1, 2, i32::MAX] {
        assert_eq!(assert_accepts(&Version(value)), json!(value));
    }
    for schema in schemas::<Amount>() {
        assert_eq!(schema.as_value()["maximum"], json!(u64::MAX));
    }
    assert_rejects::<Amount>([json!(-1), json!(0.5), json!("1")]);
    for invalid in [
        json!(-1),
        json!(u64::from(u32::MAX) + 1),
        json!(0.5),
        json!("0"),
    ] {
        assert_rejects::<Sequence>([invalid.clone()]);
        assert_rejects::<absolute::LockTime>([invalid]);
    }
    assert_rejects::<Version>([
        json!(i64::from(i32::MIN) - 1),
        json!(i64::from(i32::MAX) + 1),
        json!(0.5),
    ]);
}

#[test]
fn scripts_and_witnesses_are_hex_strings_including_empty_items() {
    for bytes in [vec![], vec![0x51], vec![0x00, 0xff, 0x4c, 0x03]] {
        let script = ScriptBuf::from_bytes(bytes.clone());
        assert_eq!(assert_accepts(&script), assert_accepts(script.as_script()));
        assert_eq!(
            serde_json::from_value::<ScriptBuf>(assert_accepts(&script)).unwrap(),
            script
        );
        let witness = Witness::from_slice(&[bytes.clone(), vec![], bytes]);
        let encoded = assert_accepts(&witness);
        assert!(encoded.as_array().unwrap().iter().all(Value::is_string));
        assert_eq!(serde_json::from_value::<Witness>(encoded).unwrap(), witness);
    }
    assert_accepts(&Witness::new());
    assert_rejects::<Script>([json!("0"), json!("gg"), json!([0, 1])]);
    assert_rejects::<ScriptBuf>([json!(null), json!("123")]);
    assert_rejects::<Witness>([json!(""), json!([[0, 1]]), json!(["0"]), json!(["zz"])]);
}

fn transaction() -> Transaction {
    Transaction {
        version: Version(i32::MIN),
        lock_time: absolute::LockTime::from_consensus(u32::MAX),
        input: vec![TxIn {
            previous_output: OutPoint::new(Txid::from_byte_array([0x12; 32]), u32::MAX),
            script_sig: ScriptBuf::from_bytes(vec![0x00, 0x51]),
            sequence: Sequence(u32::MAX),
            witness: Witness::from_slice(&[vec![], vec![0x00, 0xff]]),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(u64::MAX),
            script_pubkey: ScriptBuf::new(),
        }],
    }
}

#[test]
fn transactions_embed_actual_bitcoin_schemas_without_consensus_restrictions() {
    let transaction = transaction();
    let expected = json!({
        "version": i32::MIN,
        "lock_time": u32::MAX,
        "input": [{
            "previous_output": format!("{}:{}", "12".repeat(32), u32::MAX),
            "script_sig": "0051", "sequence": u32::MAX, "witness": ["", "00ff"]
        }],
        "output": [{"value": u64::MAX, "script_pubkey": ""}]
    });
    assert_eq!(assert_accepts(&transaction), expected);
    assert_eq!(assert_accepts(&transaction.input[0]), expected["input"][0]);
    assert_eq!(
        assert_accepts(&transaction.output[0]),
        expected["output"][0]
    );
    assert_eq!(
        assert_accepts(&transaction.input[0].previous_output),
        expected["input"][0]["previous_output"]
    );
    assert_eq!(
        serde_json::from_value::<Transaction>(expected.clone()).unwrap(),
        transaction
    );
    for name in ["version", "lock_time", "input", "output"] {
        let mut missing = expected.clone();
        missing.as_object_mut().unwrap().remove(name);
        assert_rejects::<Transaction>([missing]);
    }
    let mut old_outpoint = expected.clone();
    old_outpoint["input"][0]["previous_output"] =
        json!({"txid": "12".repeat(32), "vout": u32::MAX});
    assert_rejects::<Transaction>([old_outpoint]);
    let mut wrong_witness = expected.clone();
    wrong_witness["input"][0]["witness"] = json!([[0, 255]]);
    assert_rejects::<Transaction>([wrong_witness]);
    let mut wrong_amount = expected.clone();
    wrong_amount["output"][0]["value"] = json!(-1);
    assert_rejects::<Transaction>([wrong_amount]);
    assert_rejects::<OutPoint>([
        json!("00:0"),
        json!(format!("{}:-1", "00".repeat(32))),
        json!({}),
    ]);
    assert_accepts(&OutPoint::null());
    assert_accepts(&Transaction {
        version: Version(0),
        lock_time: absolute::LockTime::ZERO,
        input: vec![],
        output: vec![],
    });
}
