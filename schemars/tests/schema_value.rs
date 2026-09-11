use schemars::{generate::SchemaSettings, JsonSchema, Schema};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[test]
fn schema_values_agree_with_serde_without_validating_schema_keywords() {
    for settings in [SchemaSettings::draft07(), SchemaSettings::default()] {
        for settings in [settings.clone().for_serialize(), settings.for_deserialize()] {
            let schema = settings.into_generator().into_root_schema_for::<Schema>();
            let validator = jsonschema::options().build(schema.as_value()).unwrap();
            for value in [
                json!(true),
                json!(false),
                json!({}),
                json!({"type": "integer", "maximum": u64::MAX}),
                json!({"unknown-keyword": [null, 1, "anything"]}),
                // Schema accepts this object even though `type` is malformed.
                json!({"type": 7}),
            ] {
                assert!(validator.is_valid(&value));
                let decoded: Schema = serde_json::from_value(value.clone()).unwrap();
                assert_eq!(serde_json::to_value(&decoded).unwrap(), value);
                assert_eq!(decoded.as_value(), &value);
            }
            for value in [
                json!(null),
                json!([]),
                json!([{}]),
                json!("object"),
                json!(7),
            ] {
                assert!(!validator.is_valid(&value));
                assert!(serde_json::from_value::<Schema>(value).is_err());
            }
        }
    }
    assert!(jsonschema::options().build(&json!({"type": 7})).is_err());
}

#[test]
fn embedded_schemas_enforce_their_json_shape() {
    #[derive(JsonSchema, Serialize, Deserialize)]
    struct Api {
        arguments: Schema,
        returns: Schema,
    }

    let schema = SchemaSettings::draft07()
        .into_generator()
        .into_root_schema_for::<Api>();
    let validator = jsonschema::options().build(schema.as_value()).unwrap();
    let valid = json!({"arguments": false, "returns": {"x-custom": true}});
    assert!(validator.is_valid(&valid));
    let decoded: Api = serde_json::from_value(valid.clone()).unwrap();
    assert_eq!(serde_json::to_value(decoded).unwrap(), valid);

    for invalid in [
        json!({"arguments": false, "returns": []}),
        json!({"arguments": "schema", "returns": {}}),
        json!({"returns": {}}),
    ] {
        assert!(!validator.is_valid(&invalid));
        assert!(serde_json::from_value::<Api>(invalid).is_err());
    }
}
