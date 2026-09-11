#![cfg(feature = "miniscript13")]

use miniscript13::{
    descriptor::DescriptorPublicKey, policy, Descriptor, Miniscript, MiniscriptKey, Segwitv0,
};
use schemars::{generate::SchemaSettings, JsonSchema};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::{json, Value};
use std::{convert::Infallible, fmt, str::FromStr};

// Neither the symbolic key nor its associated hashes implement JsonSchema.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct Symbol(String);

impl fmt::Display for Symbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Symbol {
    type Err = Infallible;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Ok(Self(value.into()))
    }
}

impl MiniscriptKey for Symbol {
    type Sha256 = Self;
    type Hash256 = Self;
    type Ripemd160 = Self;
    type Hash160 = Self;
}

fn check_roundtrip<T>(value: &T)
where
    T: JsonSchema + Serialize + DeserializeOwned + fmt::Display + fmt::Debug + PartialEq,
{
    let encoded = serde_json::to_value(value).unwrap();
    assert_eq!(encoded, Value::String(value.to_string()));
    assert_eq!(
        &serde_json::from_value::<T>(encoded.clone()).unwrap(),
        value
    );

    // Sapio's host uses Draft 7, while standalone Schemars uses its default.
    for settings in [SchemaSettings::draft07(), SchemaSettings::default()] {
        for settings in [settings.clone().for_serialize(), settings.for_deserialize()] {
            let schema = settings.into_generator().into_root_schema_for::<T>();
            let validator = jsonschema::options().build(schema.as_value()).unwrap();
            assert!(validator.is_valid(&encoded));
            for invalid in [json!(null), json!(true), json!(42), json!([]), json!({})] {
                assert!(!validator.is_valid(&invalid), "accepted {invalid}");
                assert!(serde_json::from_value::<T>(invalid).is_err());
            }
        }
    }
}

#[test]
fn generic_keys_and_hashes_need_no_schema_implementation() {
    let concrete: policy::concrete::Policy<Symbol> =
        "and(pk(alice),sha256(payment))".parse().unwrap();
    check_roundtrip(&concrete);
    let semantic: policy::semantic::Policy<Symbol> = "or(pk(alice),pk(bob))".parse().unwrap();
    check_roundtrip(&semantic);
    let descriptor = Descriptor::new_wpkh(Symbol("alice".into())).unwrap();
    check_roundtrip(&descriptor);
    let miniscript: Miniscript<Symbol, Segwitv0> = "pk(alice)".parse().unwrap();
    check_roundtrip(&miniscript);
}

#[test]
fn bitcoin_policies_and_descriptors_match_their_serde_strings() {
    const KEY: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    let policy: policy::concrete::Policy<bitcoin032::PublicKey> =
        format!("and(pk({KEY}),older(6))").parse().unwrap();
    check_roundtrip(&policy);
    let descriptor: Descriptor<DescriptorPublicKey> =
        format!("wsh(and_v(v:pk({KEY}),older(6)))").parse().unwrap();
    check_roundtrip(&descriptor);
    let taproot: Descriptor<bitcoin032::secp256k1::XOnlyPublicKey> =
        format!("tr({})", &KEY[2..]).parse().unwrap();
    check_roundtrip(&taproot);
}

#[test]
fn schema_shape_validation_leaves_miniscript_parsing_to_serde() {
    fn parser_boundary<T: JsonSchema + DeserializeOwned>(invalid_text: &str) {
        let schema = SchemaSettings::draft07()
            .into_generator()
            .into_root_schema_for::<T>();
        let validator = jsonschema::options().build(schema.as_value()).unwrap();
        let encoded = json!(invalid_text);
        assert!(validator.is_valid(&encoded));
        assert!(serde_json::from_value::<T>(encoded).is_err());
    }

    parser_boundary::<policy::concrete::Policy<Symbol>>("unknown(alice)");
    parser_boundary::<policy::semantic::Policy<Symbol>>("unknown(alice)");
    parser_boundary::<Miniscript<Symbol, Segwitv0>>("unknown(alice)");
    parser_boundary::<Descriptor<Symbol>>("unknown(alice)");

    let descriptor = Descriptor::new_wpkh(Symbol("alice".into())).unwrap();
    let mut wrong_checksum = descriptor.to_string();
    let last = wrong_checksum.pop().unwrap();
    wrong_checksum.push(if last == 'q' { 'p' } else { 'q' });
    parser_boundary::<Descriptor<Symbol>>(&wrong_checksum);
}
