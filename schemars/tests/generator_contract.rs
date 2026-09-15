use schemars::generate::{Contract, SchemaSettings};
use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde_json::json;

#[allow(dead_code)]
#[derive(JsonSchema)]
#[serde(deny_unknown_fields)]
struct Recursive {
    #[serde(rename(serialize = "result", deserialize = "input"))]
    value: u64,
    next: Option<Box<Recursive>>,
}

fn output(generator: &mut SchemaGenerator) -> Schema {
    let previous = generator.contract().clone();
    let schema = generator.subschema_for_with_contract::<Recursive>(Contract::Serialize);
    assert_eq!(generator.contract(), &previous);
    schema
}

#[allow(dead_code)]
#[derive(JsonSchema)]
struct Interface {
    #[schemars(schema_with = "output")]
    output: Recursive,
    input: Recursive,
}

#[test]
fn mixed_contracts_share_recursive_definitions_and_restore_direction() {
    let schema = SchemaSettings::draft07()
        .into_generator()
        .into_root_schema_for::<Interface>();
    let validator = jsonschema::draft7::new(schema.as_value()).unwrap();
    let value = json!({
        "output": {"result": 1, "next": {"result": 2, "next": null}},
        "input": {"input": 3, "next": {"input": 4}}
    });
    assert!(validator.is_valid(&value));
    let mut wrong_output = value.clone();
    wrong_output["output"]["next"] = json!({"input": 2, "next": null});
    assert!(!validator.is_valid(&wrong_output));
    let mut wrong_input = value;
    wrong_input["input"]["next"] = json!({"result": 4});
    assert!(!validator.is_valid(&wrong_input));
    assert_eq!(
        schema.as_value()["definitions"].as_object().unwrap().len(),
        2
    );
}
