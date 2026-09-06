//! Single in-tree source of truth for the v3 Zone-control ResourceType
//! schemas that Nix authoring and the per-Zone resource bundle depend on.
//!
//! Two generators read this one model:
//!
//! * `gen-zone-schemas` writes
//!   `docs/reference/schemas/v3/core.d2bus.org_<Type>.schema.json`,
//!   the committed JSON Schema for the emitted canonical resource object.
//! * `gen-zone-nix-options` writes the committed generated Nix modules under
//!   `nixos-modules/generated/`.
//!
//! Keeping both behind one model is what makes the drift gate meaningful: a
//! schema change that is not reflected in the generated Nix modules cannot
//! exist, because neither artifact is hand-maintained.
//!
//! The normative ZoneLink spec is `ADR-046-resources-zone-control.md` section
//! 3.3 (exactly six top-level spec fields); the normative Zone spec is section
//! 2.3 (the empty object).

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use schemars::{JsonSchema, schema::RootSchema};
use serde_json::{Map, Value, json};

/// D113 ResourceName / Zone name spelling: 1 to 63 bytes.
const NAME_PATTERN: &str = "^[a-z][a-z0-9-]{0,62}$";
/// Same-Zone `Credential/<name>` ref.
const CREDENTIAL_REF_PATTERN: &str = "^Credential/[a-z][a-z0-9-]{0,62}$";
/// `ADR-046-resources-zone-control.md` section 3.3: the transport Provider ref
/// is required, explicit, and its local name always begins with `transport-`.
const TRANSPORT_PROVIDER_REF_PATTERN: &str = "^Provider/transport-[a-z][a-z0-9-]{0,52}$";
/// Any same-Zone `<Type>/<name>` ref, used by `metadata.ownerRef`.
const RESOURCE_REF_PATTERN: &str = "^(?:[A-Z][A-Za-z0-9]{0,62}|[a-z][a-z0-9-]{0,62}\\.d2bus\\.org\\.[A-Z][A-Za-z0-9]{0,62})/[a-z][a-z0-9-]{0,62}$";

const API_VERSION: &str = "resources.d2bus.org/v3";
const CORE_SCHEMA_NAMESPACE: &str = "core.d2bus.org";

/// The canonical 19-type registry from `ADR-046-resource-object-model`. The
/// unit test below pins it against `nixos-modules/resources.nix`, which is the
/// hand-maintained registry the structural option base already uses.
pub const STANDARD_RESOURCE_TYPES: [&str; 19] = [
    "Zone",
    "ZoneLink",
    "Provider",
    "Role",
    "RoleBinding",
    "Quota",
    "EmergencyPolicy",
    "Host",
    "Guest",
    "Process",
    "EphemeralProcess",
    "Volume",
    "Network",
    "Device",
    "User",
    "Credential",
    "Endpoint",
    "ResourceExport",
    "ResourceImport",
];

/// U12 Provider-owned qualified ResourceTypes. They are generated from their
/// signed Provider schemas and must never enter the Core standard registry.
pub const PROVIDER_OWNED_RESOURCE_TYPES: [&str; 3] = [
    "activation-nixos.d2bus.org.NixosGeneration",
    "telemetry.d2bus.org.TelemetryBinding",
    "telemetry.d2bus.org.TelemetryService",
];

/// A field default, which is also the value the bundle emitter substitutes
/// when the operator did not author the field.
#[derive(Clone, Copy)]
enum FieldDefault {
    /// Required field: no default; the emitter uses the authored value and the
    /// generated Nix module asserts presence.
    Required,
    Bool(bool),
    Int(i64),
    EmptyObject,
    EmptyList,
}

#[derive(Clone, Copy)]
enum FieldKind {
    Str {
        pattern: &'static str,
    },
    Bool,
    Int {
        min: i64,
        max: i64,
    },
    /// `types.ints.positive`: the specification states a positive integer with
    /// no declared ceiling, so no ceiling is invented here.
    PositiveInt,
    /// Closed object with a fixed, fully-defaulted member list.
    Object {
        fields: &'static [Field],
    },
    /// Provider-validated freeform object. Its members are validated at build
    /// time against the transport Provider's committed settings schema, not
    /// here.
    FreeformObject,
    StrList {
        pattern: &'static str,
        max_items: usize,
    },
}

#[derive(Clone, Copy)]
struct Field {
    name: &'static str,
    kind: FieldKind,
    default: FieldDefault,
    description: &'static str,
}

struct ResourceTypeSchema {
    name: &'static str,
    description: &'static str,
    spec_fields: &'static [Field],
}

const ZONE_LINK_LIMITS_FIELDS: &[Field] = &[
    Field {
        name: "maxActiveStreams",
        kind: FieldKind::Int { min: 1, max: 128 },
        default: FieldDefault::Int(32),
        description: "Maximum concurrently active named streams over this link.",
    },
    Field {
        name: "maxPendingIntents",
        kind: FieldKind::Int { min: 0, max: 1024 },
        default: FieldDefault::Int(256),
        description: "Maximum locally queued intents while the link is disconnected.",
    },
    Field {
        name: "reconnectMaxAttempts",
        kind: FieldKind::PositiveInt,
        default: FieldDefault::Int(10),
        description: "Maximum reconnect attempts inside one reconnect window.",
    },
    Field {
        name: "reconnectWindowSecs",
        kind: FieldKind::PositiveInt,
        default: FieldDefault::Int(300),
        description: "Length in seconds of the reconnect attempt window.",
    },
];

/// The exactly-six ZoneLink spec fields, in canonical (lexicographic) order.
const ZONE_LINK_SPEC_FIELDS: &[Field] = &[
    Field {
        name: "childZoneName",
        kind: FieldKind::Str {
            pattern: NAME_PATTERN,
        },
        default: FieldDefault::Required,
        description: "Self-reported name of the child Zone; must equal metadata.zone.",
    },
    Field {
        name: "disabled",
        kind: FieldKind::Bool,
        default: FieldDefault::Bool(false),
        description: "When true the session is closed and reconnect is suppressed.",
    },
    Field {
        name: "limits",
        kind: FieldKind::Object {
            fields: ZONE_LINK_LIMITS_FIELDS,
        },
        default: FieldDefault::EmptyObject,
        description: "Bounds on routing queues, streams, and reconnect activity.",
    },
    Field {
        name: "transportCredentials",
        kind: FieldKind::StrList {
            pattern: CREDENTIAL_REF_PATTERN,
            max_items: 8,
        },
        default: FieldDefault::EmptyList,
        description: "Same-Zone Credential refs resolved for ComponentSession establishment.",
    },
    Field {
        name: "transportProviderRef",
        kind: FieldKind::Str {
            pattern: TRANSPORT_PROVIDER_REF_PATTERN,
        },
        default: FieldDefault::Required,
        description: "Same-Zone transport Provider that owns this link's session; always explicit.",
    },
    Field {
        name: "transportSettings",
        kind: FieldKind::FreeformObject,
        default: FieldDefault::EmptyObject,
        description: "Provider-specific settings validated against the transport Provider schema.",
    },
];

const RESOURCE_TYPE_SCHEMAS: [ResourceTypeSchema; 2] = [
    ResourceTypeSchema {
        name: "Zone",
        description: "Zone store self-resource; a pure identity anchor with an empty spec.",
        spec_fields: &[],
    },
    ResourceTypeSchema {
        name: "ZoneLink",
        description: "Child-local uplink carrying transport and local route state for one parent edge.",
        spec_fields: ZONE_LINK_SPEC_FIELDS,
    },
];

impl FieldDefault {
    fn as_json(self) -> Option<Value> {
        match self {
            FieldDefault::Required => None,
            FieldDefault::Bool(value) => Some(Value::Bool(value)),
            FieldDefault::Int(value) => Some(Value::from(value)),
            FieldDefault::EmptyObject => Some(json!({})),
            FieldDefault::EmptyList => Some(json!([])),
        }
    }
}

impl Field {
    fn json_schema(&self) -> Value {
        let mut schema = match self.kind {
            FieldKind::Str { pattern } => json!({ "type": "string", "pattern": pattern }),
            FieldKind::Bool => json!({ "type": "boolean" }),
            FieldKind::Int { min, max } => {
                json!({ "type": "integer", "minimum": min, "maximum": max })
            }
            FieldKind::PositiveInt => json!({ "type": "integer", "minimum": 1 }),
            FieldKind::Object { fields } => object_schema(fields),
            FieldKind::FreeformObject => json!({ "type": "object" }),
            FieldKind::StrList { pattern, max_items } => json!({
                "type": "array",
                "maxItems": max_items,
                "items": { "type": "string", "pattern": pattern },
            }),
        };
        if self.name == "transportProviderRef" {
            schema = resource_ref_schema_with(TRANSPORT_PROVIDER_REF_PATTERN, &["Provider"]);
        } else if self.name == "transportCredentials" {
            schema = json!({
                "type": "array",
                "maxItems": 8,
                "items": resource_ref_schema_with(CREDENTIAL_REF_PATTERN, &["Credential"]),
            });
        }
        let object = schema
            .as_object_mut()
            .expect("field schema is always a JSON object");
        object.insert("description".to_owned(), Value::from(self.description));
        if let Some(default) = self.default.as_json()
            && !matches!(self.kind, FieldKind::Object { .. })
        {
            object.insert("default".to_owned(), default);
        }
        schema
    }

    /// Human-readable constraint clause used in the generated Nix assertion
    /// message. It names the exact bound so an operator can fix the value
    /// without reading the schema.
    fn constraint_text(&self) -> String {
        match self.kind {
            FieldKind::Str { pattern } => format!("must be a string matching {pattern}"),
            FieldKind::Bool => "must be a boolean".to_owned(),
            FieldKind::Int { min, max } => {
                format!("must be an integer between {min} and {max}")
            }
            FieldKind::PositiveInt => "must be a positive integer".to_owned(),
            FieldKind::Object { fields } => {
                let names: Vec<&str> = fields.iter().map(|field| field.name).collect();
                format!(
                    "must be an attribute set whose keys are drawn from {}",
                    names.join(", ")
                )
            }
            FieldKind::FreeformObject => "must be an attribute set".to_owned(),
            FieldKind::StrList { pattern, max_items } => {
                format!("must be a list of at most {max_items} strings matching {pattern}")
            }
        }
    }
}

fn object_schema(fields: &[Field]) -> Value {
    let mut properties = serde_json::Map::new();
    let mut required = Vec::new();
    for field in fields {
        properties.insert(field.name.to_owned(), field.json_schema());
        // The emitter always renders every declared field, defaulted fields
        // included, so every declared field is required in the emitted object.
        required.push(Value::from(field.name));
    }
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": Value::Object(properties),
        "required": Value::Array(required),
    })
}

fn metadata_schema(type_name: &str) -> Value {
    let zone_description = if type_name == "Zone" {
        "Zone self-name; equals metadata.name for the Zone self-resource."
    } else {
        "Name of the Zone this resource is local to."
    };
    let mut properties = Map::new();
    properties.insert(
        "annotations".to_owned(),
        json!({
            "type": "object",
            "additionalProperties": { "type": "string" },
            "description": "Optional authored key-value annotation map.",
        }),
    );
    properties.insert(
        "labels".to_owned(),
        json!({
            "type": "object",
            "additionalProperties": { "type": "string" },
            "description": "Optional authored key-value label map.",
        }),
    );
    properties.insert(
        "name".to_owned(),
        json!({
            "type": "string",
            "pattern": NAME_PATTERN,
            "description": "Zone-local resource name.",
        }),
    );
    let mut owner_ref = resource_ref_schema();
    owner_ref
        .as_object_mut()
        .expect("ResourceRef schema is an object")
        .insert(
            "description".to_owned(),
            Value::String("Optional same-Zone ref of the owning resource.".to_owned()),
        );
    properties.insert("ownerRef".to_owned(), owner_ref);
    properties.insert(
        "zone".to_owned(),
        json!({
            "type": "string",
            "pattern": NAME_PATTERN,
            "description": zone_description,
        }),
    );
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["name", "zone"],
        "properties": Value::Object(properties),
    })
}

fn resource_schema(schema: &ResourceTypeSchema) -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": format!(
            "https://d2bus.org/schemas/v3/{}",
            core_schema_artifact_name(schema.name)
        ),
        "title": schema.name,
        "description": schema.description,
        "x-d2b-resource-type": schema.name,
        "type": "object",
        "additionalProperties": false,
        "required": ["apiVersion", "metadata", "spec", "type"],
        "properties": {
            "apiVersion": { "const": API_VERSION },
            "metadata": metadata_schema(schema.name),
            "spec": object_schema(schema.spec_fields),
            "type": { "const": schema.name },
        },
    })
}

fn string_schema(pattern: &str) -> Value {
    json!({
        "type": "string",
        "pattern": pattern,
    })
}

fn bounded_string(min_length: usize, max_length: usize) -> Value {
    json!({
        "type": "string",
        "minLength": min_length,
        "maxLength": max_length,
    })
}

fn enum_schema(values: &[&str]) -> Value {
    json!({
        "type": "string",
        "enum": values,
    })
}

fn nullable(schema: Value) -> Value {
    json!({
        "anyOf": [
            schema,
            { "type": "null" },
        ],
    })
}

fn resource_ref_schema() -> Value {
    resource_ref_schema_with(RESOURCE_REF_PATTERN, &[])
}

fn provider_ref_schema() -> Value {
    resource_ref_schema_with("^Provider/[a-z][a-z0-9-]{0,62}$", &["Provider"])
}

fn resource_ref_schema_with(pattern: &str, allowed_types: &[&str]) -> Value {
    let mut schema = string_schema(pattern);
    let object = schema
        .as_object_mut()
        .expect("ResourceRef schema is an object");
    object.insert(
        "x-d2b-reference-kind".to_owned(),
        Value::String("ResourceRef".to_owned()),
    );
    object.insert(
        "x-d2b-allowed-ref-types".to_owned(),
        Value::Array(
            allowed_types
                .iter()
                .map(|value| Value::String((*value).to_owned()))
                .collect(),
        ),
    );
    object.insert(
        "x-d2b-reference-scope".to_owned(),
        Value::String("same-zone".to_owned()),
    );
    schema
}

fn array_schema(items: Value, max_items: usize) -> Value {
    json!({
        "type": "array",
        "maxItems": max_items,
        "items": items,
    })
}

fn object_schema_value(
    properties: Map<String, Value>,
    required: &[&str],
    additional_properties: bool,
) -> Value {
    json!({
        "type": "object",
        "additionalProperties": additional_properties,
        "properties": Value::Object(properties),
        "required": required,
    })
}

fn object_from_pairs(
    pairs: impl IntoIterator<Item = (&'static str, Value)>,
    required: &[&str],
) -> Value {
    object_schema_value(
        pairs
            .into_iter()
            .map(|(name, value)| (name.to_owned(), value))
            .collect(),
        required,
        false,
    )
}

fn provider_extension_schema() -> Value {
    object_from_pairs(
        [
            ("schemaId", bounded_string(1, 201)),
            ("schemaVersion", bounded_string(3, 32)),
            ("settings", json!({ "type": "object" })),
        ],
        &["schemaId", "schemaVersion", "settings"],
    )
}

fn update_policy_schema() -> Value {
    object_from_pairs(
        [(
            "mode",
            enum_schema(&["manual", "automatic", "manual-disruptive"]),
        )],
        &[],
    )
}

fn with_universal_spec_fields(name: &str, mut spec: Value) -> Value {
    let object = spec
        .as_object_mut()
        .expect("ResourceType spec schemas are objects");
    let properties = object
        .entry("properties")
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .expect("ResourceType spec properties are an object");

    if name != "Provider" && name != "Zone" && name != "ZoneLink" {
        properties
            .entry("providerRef".to_owned())
            .or_insert_with(provider_ref_schema);
        properties
            .entry("updatePolicy".to_owned())
            .or_insert_with(update_policy_schema);
    }

    if matches!(
        name,
        "Host"
            | "Guest"
            | "Process"
            | "EphemeralProcess"
            | "Volume"
            | "Network"
            | "Device"
            | "Credential"
            | "Endpoint"
            | "ResourceExport"
            | "ResourceImport"
    ) {
        properties
            .entry("provider".to_owned())
            .or_insert_with(provider_extension_schema);
    }

    object.insert("additionalProperties".to_owned(), Value::Bool(false));
    spec
}

fn strict_spec(mut spec: Value) -> Value {
    spec.as_object_mut()
        .expect("ResourceType spec schemas are objects")
        .insert("additionalProperties".to_owned(), Value::Bool(false));
    spec
}

fn dto_resource_schema<T: JsonSchema>(
    name: &str,
    description: &str,
    include_universal_fields: bool,
) -> Value {
    let root: RootSchema = schemars::schema_for!(T);
    let definitions = serde_json::to_value(&root.definitions).expect("schema definitions render");
    let raw_spec = serde_json::to_value(&root.schema).expect("schema renders");
    let spec = if include_universal_fields {
        with_universal_spec_fields(name, raw_spec)
    } else {
        strict_spec(raw_spec)
    };
    let mut resource = resource_envelope_schema(name, description, spec);
    if definitions != json!({}) {
        resource
            .as_object_mut()
            .expect("resource schema is an object")
            .insert("definitions".to_owned(), definitions);
    }
    annotate_resource_ref_schemas(&mut resource);
    resource
}

fn annotate_resource_ref_schemas(schema: &mut Value) {
    match schema {
        Value::Object(object) => {
            if object.get("$ref").and_then(Value::as_str) == Some("#/definitions/ResourceRef") {
                object.insert(
                    "x-d2b-reference-kind".to_owned(),
                    Value::String("ResourceRef".to_owned()),
                );
                object.insert(
                    "x-d2b-reference-scope".to_owned(),
                    Value::String("same-zone".to_owned()),
                );
            }
            if let Some(definitions) = object.get_mut("definitions").and_then(Value::as_object_mut)
                && let Some(resource_ref) = definitions.get_mut("ResourceRef")
                && let Some(resource_ref) = resource_ref.as_object_mut()
            {
                resource_ref.insert(
                    "x-d2b-reference-kind".to_owned(),
                    Value::String("ResourceRef".to_owned()),
                );
                resource_ref.insert(
                    "x-d2b-reference-scope".to_owned(),
                    Value::String("same-zone".to_owned()),
                );
            }
            let ref_property_names = object
                .keys()
                .filter(|name| name.ends_with("Ref"))
                .cloned()
                .collect::<Vec<_>>();
            for name in ref_property_names {
                if object.get(&name).is_some_and(contains_resource_ref_schema)
                    && let Some(property) = object.get_mut(&name).and_then(Value::as_object_mut)
                {
                    property.insert(
                        "x-d2b-reference-kind".to_owned(),
                        Value::String("ResourceRef".to_owned()),
                    );
                    property.insert(
                        "x-d2b-reference-scope".to_owned(),
                        Value::String("same-zone".to_owned()),
                    );
                }
            }
            for value in object.values_mut() {
                annotate_resource_ref_schemas(value);
            }
        }
        Value::Array(values) => {
            for value in values {
                annotate_resource_ref_schemas(value);
            }
        }

        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

fn contains_resource_ref_schema(value: &Value) -> bool {
    match value {
        Value::Object(object) => {
            object.get("$ref").and_then(Value::as_str) == Some("#/definitions/ResourceRef")
                || object.values().any(contains_resource_ref_schema)
        }
        Value::Array(values) => values.iter().any(contains_resource_ref_schema),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => false,
    }
}

fn resource_envelope_schema(name: &str, description: &str, spec: Value) -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": format!(
            "https://d2bus.org/schemas/v3/{}",
            core_schema_artifact_name(name)
        ),
        "title": name,
        "description": description,
        "x-d2b-resource-type": name,
        "type": "object",
        "additionalProperties": false,
        "required": ["apiVersion", "metadata", "spec", "type"],
        "properties": {
            "apiVersion": { "const": API_VERSION },
            "metadata": metadata_schema(name),
            "spec": spec,
            "type": { "const": name },
        },
    })
}

fn core_resource_schema(name: &str, description: &str, spec: Value) -> Value {
    resource_envelope_schema(name, description, with_universal_spec_fields(name, spec))
}

fn role_rule_schema() -> Value {
    object_from_pairs(
        [
            (
                "resourceTypes",
                array_schema(string_schema(RESOURCE_TYPE_NAME_PATTERN), 16),
            ),
            (
                "verbs",
                array_schema(
                    enum_schema(&[
                        "get",
                        "list",
                        "watch",
                        "create",
                        "update-spec",
                        "update-status",
                        "update-metadata",
                        "update-finalizers",
                        "delete",
                        "use-credential",
                        "admin-credential",
                    ]),
                    16,
                ),
            ),
            ("subresources", array_schema(bounded_string(0, 201), 16)),
            (
                "resourceNames",
                array_schema(string_schema(NAME_PATTERN), 64),
            ),
            ("zones", array_schema(string_schema(NAME_PATTERN), 8)),
            ("executionRefs", array_schema(resource_ref_schema(), 32)),
            (
                "sessionVerbs",
                array_schema(
                    enum_schema(&[
                        "connect",
                        "invoke",
                        "open-stream",
                        "relay",
                        "attach",
                        "cancel",
                        "observe",
                        "audit-export",
                        "support-bundle",
                    ]),
                    9,
                ),
            ),
        ],
        &[
            "resourceTypes",
            "verbs",
            "subresources",
            "resourceNames",
            "zones",
            "executionRefs",
            "sessionVerbs",
        ],
    )
}

const RESOURCE_TYPE_NAME_PATTERN: &str =
    "^[A-Z][A-Za-z0-9]{0,62}$|^[a-z][a-z0-9-]{0,62}\\.d2bus\\.org\\.[A-Z][A-Za-z0-9]{0,62}$";

fn standard_core_schemas() -> Vec<(&'static str, Value)> {
    let role = core_resource_schema(
        "Role",
        "Zone-local bounded authorization rules.",
        object_from_pairs(
            [("rules", array_schema(role_rule_schema(), 32))],
            &["rules"],
        ),
    );
    let role_binding = core_resource_schema(
        "RoleBinding",
        "Zone-local binding of a Role to authenticated subjects.",
        object_from_pairs(
            [
                (
                    "roleRef",
                    resource_ref_schema_with("^Role/[a-z][a-z0-9-]{0,62}$", &["Role"]),
                ),
                ("subjects", array_schema(resource_ref_schema(), 64)),
                (
                    "externalPrincipalSelector",
                    nullable(json!({ "type": "object" })),
                ),
                ("scopeNarrowing", nullable(json!({ "type": "object" }))),
            ],
            &[
                "roleRef",
                "subjects",
                "externalPrincipalSelector",
                "scopeNarrowing",
            ],
        ),
    );
    let quota = core_resource_schema(
        "Quota",
        "Zone-wide aggregate resource ceilings.",
        object_from_pairs(
            [
                (
                    "ceilings",
                    object_from_pairs(
                        [
                            (
                                "maxResources",
                                json!({ "type": "integer", "minimum": 1, "maximum": 65536 }),
                            ),
                            (
                                "maxResourcesPerType",
                                json!({ "type": "integer", "minimum": 1, "maximum": 65536 }),
                            ),
                            (
                                "maxOwnerDepth",
                                json!({ "type": "integer", "minimum": 1, "maximum": 32 }),
                            ),
                            (
                                "maxCpu",
                                nullable(json!({ "type": "integer", "minimum": 1 })),
                            ),
                            (
                                "maxMemoryMib",
                                nullable(json!({ "type": "integer", "minimum": 1 })),
                            ),
                            (
                                "maxStorageGib",
                                nullable(json!({ "type": "integer", "minimum": 1 })),
                            ),
                        ],
                        &[
                            "maxResources",
                            "maxResourcesPerType",
                            "maxOwnerDepth",
                            "maxCpu",
                            "maxMemoryMib",
                            "maxStorageGib",
                        ],
                    ),
                ),
                (
                    "perTypeCeilings",
                    json!({
                        "type": "object",
                        "maxProperties": 64,
                        "additionalProperties": { "type": "object" },
                    }),
                ),
                ("scope", enum_schema(&["zone"])),
                ("enforcementPolicy", enum_schema(&["hard", "soft"])),
            ],
            &["ceilings", "perTypeCeilings", "scope", "enforcementPolicy"],
        ),
    );
    let emergency_policy = core_resource_schema(
        "EmergencyPolicy",
        "Zone-wide emergency admission and drain policy.",
        object_from_pairs(
            [
                ("enabled", json!({ "type": "boolean" })),
                (
                    "scope",
                    object_from_pairs(
                        [
                            ("stopNewAdmissions", json!({ "type": "boolean" })),
                            ("disconnectZoneLinks", json!({ "type": "boolean" })),
                            ("stopProviderProcesses", json!({ "type": "boolean" })),
                            ("drainOngoingOperations", json!({ "type": "boolean" })),
                        ],
                        &[
                            "stopNewAdmissions",
                            "disconnectZoneLinks",
                            "stopProviderProcesses",
                            "drainOngoingOperations",
                        ],
                    ),
                ),
                (
                    "drainDeadlineSeconds",
                    json!({ "type": "integer", "minimum": 1, "maximum": 300 }),
                ),
                ("reason", bounded_string(0, 256)),
            ],
            &["enabled", "scope", "drainDeadlineSeconds", "reason"],
        ),
    );
    let endpoint = core_resource_schema(
        "Endpoint",
        "Stable provider-neutral endpoint identity without a locator.",
        object_from_pairs(
            [
                ("producerRef", resource_ref_schema()),
                (
                    "endpointClass",
                    enum_schema(&["service", "device", "transport", "control", "data"]),
                ),
                (
                    "transport",
                    enum_schema(&["unix", "vsock", "tcp", "fd-attachment", "opaque-carriage"]),
                ),
                ("purpose", bounded_string(1, 63)),
                ("serviceFingerprint", nullable(bounded_string(0, 71))),
                (
                    "locality",
                    enum_schema(&["host-local", "guest-local", "cross-domain", "zone-local"]),
                ),
                ("visibility", enum_schema(&["owner", "provider", "zone"])),
                (
                    "attachmentPolicy",
                    object_from_pairs(
                        [
                            ("supported", json!({ "type": "boolean" })),
                            (
                                "maxAttachments",
                                json!({ "type": "integer", "minimum": 0, "maximum": 64 }),
                            ),
                        ],
                        &["supported", "maxAttachments"],
                    ),
                ),
                (
                    "consumerPolicy",
                    object_from_pairs(
                        [
                            ("allowedSubjects", array_schema(resource_ref_schema(), 64)),
                            (
                                "allowedProviderComponents",
                                array_schema(bounded_string(1, 63), 32),
                            ),
                            (
                                "allowedOperations",
                                array_schema(enum_schema(&["resolve", "attach", "observe"]), 3),
                            ),
                        ],
                        &[
                            "allowedSubjects",
                            "allowedProviderComponents",
                            "allowedOperations",
                        ],
                    ),
                ),
                (
                    "lifecyclePolicy",
                    enum_schema(&["pinned", "recycle-with-producer", "recreate-on-generation"]),
                ),
            ],
            &[
                "producerRef",
                "endpointClass",
                "transport",
                "purpose",
                "serviceFingerprint",
                "locality",
                "visibility",
                "attachmentPolicy",
                "consumerPolicy",
                "lifecyclePolicy",
            ],
        ),
    );
    let export = core_resource_schema(
        "ResourceExport",
        "Owner-Zone advertisement of one semantic Service authority.",
        object_from_pairs(
            [
                (
                    "providerRef",
                    resource_ref_schema_with("^Provider/[a-z][a-z0-9-]{0,62}$", &["Provider"]),
                ),
                ("resourceRef", resource_ref_schema()),
                ("serviceType", string_schema(RESOURCE_TYPE_NAME_PATTERN)),
                (
                    "projectionSchemaFingerprint",
                    string_schema("^sha256:[0-9a-f]{64}$"),
                ),
                ("factoryFingerprint", string_schema("^sha256:[0-9a-f]{64}$")),
                ("operations", array_schema(bounded_string(1, 63), 64)),
                (
                    "arbitration",
                    enum_schema(&["exclusive", "shared", "multiplexed"]),
                ),
                ("quota", json!({ "type": "object" })),
                ("consumerZonePolicy", json!({ "type": "object" })),
                ("visibility", enum_schema(&["child-zones", "named-zones"])),
                ("updatePolicy", json!({ "type": "object" })),
                ("revocationPolicy", json!({ "type": "object" })),
            ],
            &[
                "providerRef",
                "resourceRef",
                "serviceType",
                "projectionSchemaFingerprint",
                "factoryFingerprint",
                "operations",
                "arbitration",
                "quota",
                "consumerZonePolicy",
                "visibility",
                "updatePolicy",
                "revocationPolicy",
            ],
        ),
    );
    let import = core_resource_schema(
        "ResourceImport",
        "Consumer-Zone route to one remote semantic Service authority.",
        object_from_pairs(
            [
                (
                    "providerRef",
                    resource_ref_schema_with("^Provider/[a-z][a-z0-9-]{0,62}$", &["Provider"]),
                ),
                (
                    "zoneLinkRef",
                    resource_ref_schema_with("^ZoneLink/[a-z][a-z0-9-]{0,62}$", &["ZoneLink"]),
                ),
                ("exportKey", bounded_string(1, 128)),
                (
                    "expectedServiceType",
                    string_schema(RESOURCE_TYPE_NAME_PATTERN),
                ),
                (
                    "expectedProjectionSchemaFingerprint",
                    string_schema("^sha256:[0-9a-f]{64}$"),
                ),
                (
                    "expectedFactoryFingerprint",
                    string_schema("^sha256:[0-9a-f]{64}$"),
                ),
                ("projectionName", string_schema(NAME_PATTERN)),
                (
                    "requestedCapabilities",
                    array_schema(bounded_string(1, 63), 64),
                ),
                ("requestedQuota", json!({ "type": "object" })),
                ("updatePolicy", json!({ "type": "object" })),
                ("disconnectPolicy", json!({ "type": "object" })),
            ],
            &[
                "providerRef",
                "zoneLinkRef",
                "exportKey",
                "expectedServiceType",
                "expectedProjectionSchemaFingerprint",
                "expectedFactoryFingerprint",
                "projectionName",
                "requestedCapabilities",
                "requestedQuota",
                "updatePolicy",
                "disconnectPolicy",
            ],
        ),
    );
    vec![
        ("Role", role),
        ("RoleBinding", role_binding),
        ("Quota", quota),
        ("EmergencyPolicy", emergency_policy),
        ("Endpoint", endpoint),
        ("ResourceExport", export),
        ("ResourceImport", import),
    ]
}

fn standard_resource_schemas() -> Vec<(&'static str, Value)> {
    let mut schemas = vec![
        ("Zone", resource_schema(&RESOURCE_TYPE_SCHEMAS[0])),
        ("ZoneLink", resource_schema(&RESOURCE_TYPE_SCHEMAS[1])),
        (
            "Provider",
            dto_resource_schema::<d2b_contracts_provider::v3::provider::ProviderSpec>(
                "Provider",
                "Installed Provider package selection and schema-bound configuration.",
                false,
            ),
        ),
        (
            "Host",
            dto_resource_schema::<d2b_contracts_resource::v3::host::HostSpec>(
                "Host",
                "Physical or local execution and policy parent.",
                true,
            ),
        ),
        (
            "Guest",
            dto_resource_schema::<d2b_contracts_resource::v3::guest::GuestSpec>(
                "Guest",
                "VM, sandbox, cloud, or remote execution parent.",
                true,
            ),
        ),
        (
            "Process",
            dto_resource_schema::<d2b_contracts_resource::v3::process::ProcessSpec>(
                "Process",
                "Long-lived Provider-managed process.",
                true,
            ),
        ),
        (
            "EphemeralProcess",
            dto_resource_schema::<d2b_contracts_resource::v3::process::EphemeralProcessSpec>(
                "EphemeralProcess",
                "One-shot Provider-managed process.",
                true,
            ),
        ),
        (
            "Volume",
            dto_resource_schema::<d2b_contracts_resource::v3::volume::VolumeSpec>(
                "Volume",
                "Shareable storage resource with bounded views and attachments.",
                true,
            ),
        ),
        (
            "Network",
            dto_resource_schema::<d2b_contracts_resource::v3::network::NetworkSpec>(
                "Network",
                "Zone-local network fabric.",
                true,
            ),
        ),
        (
            "Device",
            dto_resource_schema::<d2b_contracts_resource::v3::device::DeviceSpec>(
                "Device",
                "Inventoried physical or emulated device.",
                true,
            ),
        ),
        (
            "User",
            dto_resource_schema::<d2b_contracts_resource::v3::user::UserSpec>(
                "User",
                "Zone-local named operating-system identity.",
                false,
            ),
        ),
        (
            "Credential",
            dto_resource_schema::<d2b_contracts_provider::v3::credential::CredentialSpec>(
                "Credential",
                "Opaque rotating credential lease policy.",
                true,
            ),
        ),
    ];
    schemas.extend(standard_core_schemas());
    schemas.sort_by(|left, right| left.0.cmp(right.0));
    schemas
}

/// Return the committed artifact name for a standard ResourceType schema.
///
/// Qualified Provider schemas already carry their namespace in the committed
/// filename.  The standard catalog uses the same flattened namespace shape so
/// a schema filename is unambiguous without changing the API ResourceType
/// spelling or its schema title.
pub(crate) fn core_schema_artifact_name(resource_type: &str) -> String {
    format!("{CORE_SCHEMA_NAMESPACE}_{resource_type}.schema.json")
}

/// `gen-zone-schemas`: emit the committed JSON Schema for every Zone-control
/// ResourceType this model owns.
pub fn gen_zone_schemas(repo_root: &Path) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let out_dir = repo_root.join("docs/reference/schemas/v3");
    fs::create_dir_all(&out_dir)?;

    let mut written = Vec::new();
    for (name, schema) in standard_resource_schemas() {
        let path = out_dir.join(core_schema_artifact_name(name));
        let mut data = serde_json::to_string_pretty(&schema)?;
        data.push('\n');
        fs::write(&path, data)?;
        written.push(path);
    }
    Ok(written)
}

const GENERATED_HEADER: &str = concat!(
    "# Generated by `bazel run //packages/xtask:xtask -- gen-zone-nix-options`.\n",
    "# Do not hand-edit: `make test-drift` compares this\n",
    "# file byte-for-byte against the generator output.\n",
);

fn nix_string(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len() + 2);
    escaped.push('"');
    for character in value.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '$' => escaped.push_str("\\$"),
            '\n' => escaped.push_str("\\n"),
            other => escaped.push(other),
        }
    }
    escaped.push('"');
    escaped
}

/// Render the flattened field-spec rows the generated assertion interpreter
/// consumes. Nested closed objects contribute one row for the container plus
/// one row per member, so bounds on `limits.*` are enforced individually.
fn field_spec_rows(fields: &[Field], prefix: &[&str], rows: &mut Vec<String>) {
    for field in fields {
        let mut path: Vec<&str> = prefix.to_vec();
        path.push(field.name);
        let path_literal = path
            .iter()
            .map(|segment| nix_string(segment))
            .collect::<Vec<_>>()
            .join(" ");
        let required = matches!(field.default, FieldDefault::Required);
        let mut row = format!(
            "    {{ path = [ {path_literal} ]; required = {}; ",
            if required { "true" } else { "false" }
        );
        match field.kind {
            FieldKind::Str { pattern } => {
                row.push_str(&format!(
                    "kind = \"string\"; pattern = {}; ",
                    nix_string(pattern)
                ));
            }
            FieldKind::Bool => row.push_str("kind = \"bool\"; "),
            FieldKind::Int { min, max } => {
                row.push_str(&format!("kind = \"int\"; min = {min}; max = {max}; "));
            }
            FieldKind::PositiveInt => row.push_str("kind = \"positiveInt\"; "),
            FieldKind::Object { fields } => {
                let keys = fields
                    .iter()
                    .map(|member| nix_string(member.name))
                    .collect::<Vec<_>>()
                    .join(" ");
                row.push_str(&format!(
                    "kind = \"object\"; closed = true; keys = [ {keys} ]; "
                ));
            }
            FieldKind::FreeformObject => row.push_str("kind = \"object\"; closed = false; "),
            FieldKind::StrList { pattern, max_items } => {
                row.push_str(&format!(
                    "kind = \"stringList\"; pattern = {}; maxItems = {max_items}; ",
                    nix_string(pattern)
                ));
            }
        }
        row.push_str(&format!(
            "constraint = {}; }}",
            nix_string(&field.constraint_text())
        ));
        rows.push(row);

        if let FieldKind::Object { fields } = field.kind {
            field_spec_rows(fields, &path, rows);
        }
    }
}

const ASSERTION_INTERPRETER: &str = r#"
  lookup = value: path:
    lib.foldl'
      (acc: key:
        if acc.found && builtins.isAttrs acc.value && builtins.hasAttr key acc.value
        then { found = true; value = acc.value.${key}; }
        else { found = false; value = null; })
      { found = true; value = value; }
      path;

  satisfies = field: value:
    if field.kind == "string" then
      builtins.isString value && builtins.match field.pattern value != null
    else if field.kind == "bool" then
      builtins.isBool value
    else if field.kind == "int" then
      builtins.isInt value && value >= field.min && value <= field.max
    else if field.kind == "positiveInt" then
      builtins.isInt value && value >= 1
    else if field.kind == "object" then
      builtins.isAttrs value
      && (!field.closed
        || lib.all (key: builtins.elem key field.keys) (builtins.attrNames value))
    else if field.kind == "stringList" then
      builtins.isList value
      && lib.length value <= field.maxItems
      && lib.all
        (entry: builtins.isString entry && builtins.match field.pattern entry != null)
        value
    else
      false;

  fieldAssertions = zoneName: resourceName: resource:
    let
      base = "d2b.zones.${zoneName}.resources.${resourceName}.spec";
    in
    map
      (field:
        let
          rendered = lib.concatStringsSep "." field.path;
          probe = lookup resource.spec field.path;
        in
        if !probe.found then {
          assertion = !field.required;
          message =
            "${base}.${rendered} is required for ${resourceType} resources.";
        } else {
          assertion = satisfies field probe.value;
          message = "${base}.${rendered} ${field.constraint}.";
        })
      fieldSpecs;

  typedResourceAssertions = lib.flatten (lib.mapAttrsToList
    (zoneName: zone:
      lib.mapAttrsToList
        (resourceName: resource:
          if resource.type == resourceType
          then fieldAssertions zoneName resourceName resource
          else [ ])
        zone.resources)
    config.d2b.zones);
in
{
  config.assertions = typedResourceAssertions;
}
"#;

fn generated_options_module(schema: &ResourceTypeSchema) -> String {
    let mut rows = Vec::new();
    field_spec_rows(schema.spec_fields, &[], &mut rows);
    let schema_file = core_schema_artifact_name(schema.name);

    let mut out = String::new();
    out.push_str(GENERATED_HEADER);
    out.push_str(&format!(
        "# Source of truth: docs/reference/schemas/v3/{schema_file}\n",
    ));
    out.push_str(&format!(
        "#\n# Field-level type, pattern, bound, and required checks for every\n\
         # d2b.zones.<zone>.resources.<name> declaring type = \"{}\".\n",
        schema.name
    ));
    out.push_str("{ config, lib, ... }:\n\nlet\n");
    out.push_str(&format!(
        "  resourceType = {};\n\n",
        nix_string(schema.name)
    ));
    if rows.is_empty() {
        out.push_str("  # This ResourceType has an empty canonical spec object.\n");
        out.push_str("  fieldSpecs = [ ];\n");
    } else {
        out.push_str("  fieldSpecs = [\n");
        for row in &rows {
            out.push_str(row);
            out.push('\n');
        }
        out.push_str("  ];\n");
    }
    out.push_str(ASSERTION_INTERPRETER);
    out
}

fn nix_default_literal(field: &Field, indent: usize) -> String {
    let pad = " ".repeat(indent);
    match (field.kind, field.default) {
        (FieldKind::Object { fields }, FieldDefault::EmptyObject) if !fields.is_empty() => {
            let mut out = String::from("{\n");
            for member in fields {
                out.push_str(&format!(
                    "{pad}  {} = {};\n",
                    member.name,
                    nix_default_literal(member, indent + 2)
                ));
            }
            out.push_str(&format!("{pad}}}"));
            out
        }
        (_, FieldDefault::Required) => "null".to_owned(),
        (_, FieldDefault::Bool(value)) => value.to_string(),
        (_, FieldDefault::Int(value)) => value.to_string(),
        (_, FieldDefault::EmptyObject) => "{ }".to_owned(),
        (_, FieldDefault::EmptyList) => "[ ]".to_owned(),
    }
}

fn generated_spec_canonical_module() -> String {
    let mut out = String::new();
    out.push_str(GENERATED_HEADER);
    out.push_str(
        "#\n\
         # Canonical spec projection table consumed by\n\
         # nixos-modules/zone-resources-json.nix. For each ResourceType this\n\
         # model owns, `fields` is the canonical (lexicographically sorted)\n\
         # top-level spec field list and `defaults` carries the value the\n\
         # emitter substitutes when the operator did not author the field.\n\
         # A required field has no default and is rendered as null here; the\n\
         # generated per-type assertions reject an absent required field\n\
         # before the emitter can observe one.\n",
    );
    out.push_str("{\n");
    for schema in &RESOURCE_TYPE_SCHEMAS {
        out.push_str(&format!("  {} = {{\n", schema.name));
        let names = schema
            .spec_fields
            .iter()
            .map(|field| nix_string(field.name))
            .collect::<Vec<_>>()
            .join(" ");
        if schema.spec_fields.is_empty() {
            out.push_str("    fields = [ ];\n");
            out.push_str("    defaults = { };\n");
        } else {
            out.push_str(&format!("    fields = [ {names} ];\n"));
            out.push_str("    defaults = {\n");
            for field in schema.spec_fields {
                out.push_str(&format!(
                    "      {} = {};\n",
                    field.name,
                    nix_default_literal(field, 6)
                ));
            }
            out.push_str("    };\n");
        }
        out.push_str("  };\n");
    }
    out.push_str("}\n");
    out
}

fn generated_resource_types_module() -> String {
    let mut out = String::new();
    out.push_str(GENERATED_HEADER);
    out.push_str(
        "#\n\
         # The canonical ADR 0046 standard ResourceType registry. Qualified\n\
         # Provider types are appended only from installed signed schemas and\n\
         # are therefore absent here.\n",
    );
    out.push_str(&format!(
        "# Provider-owned qualified types remain outside this registry: {}.\n",
        PROVIDER_OWNED_RESOURCE_TYPES.join(", ")
    ));
    out.push_str("[\n");
    for name in STANDARD_RESOURCE_TYPES {
        out.push_str(&format!("  {}\n", nix_string(name)));
    }
    out.push_str("]\n");
    out
}

/// `gen-zone-nix-options`: emit the committed generated Nix modules.
pub fn gen_zone_nix_options(repo_root: &Path) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let out_dir = repo_root.join("nixos-modules/generated");
    fs::create_dir_all(&out_dir)?;

    let mut files: BTreeMap<PathBuf, String> = BTreeMap::new();
    for schema in &RESOURCE_TYPE_SCHEMAS {
        files.insert(
            out_dir.join(format!("options-zones-{}.nix", schema.name)),
            generated_options_module(schema),
        );
    }
    files.insert(
        out_dir.join("resource-types.nix"),
        generated_resource_types_module(),
    );
    files.insert(
        out_dir.join("zone-spec-canonical.nix"),
        generated_spec_canonical_module(),
    );

    let mut written = Vec::new();
    for (path, contents) in files {
        fs::write(&path, contents)?;
        written.push(path);
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo_root() -> PathBuf {
        crate::repo_root().expect("repo root").to_path_buf()
    }

    #[test]
    fn zone_link_spec_has_exactly_the_canonical_six_fields() {
        let names: Vec<&str> = ZONE_LINK_SPEC_FIELDS
            .iter()
            .map(|field| field.name)
            .collect();
        assert_eq!(
            names,
            vec![
                "childZoneName",
                "disabled",
                "limits",
                "transportCredentials",
                "transportProviderRef",
                "transportSettings",
            ]
        );
    }

    #[test]
    fn spec_fields_are_lexicographically_sorted() {
        for schema in &RESOURCE_TYPE_SCHEMAS {
            let names: Vec<&str> = schema.spec_fields.iter().map(|field| field.name).collect();
            let mut sorted = names.clone();
            sorted.sort_unstable();
            assert_eq!(names, sorted, "{} spec fields must be sorted", schema.name);
        }
    }

    #[test]
    fn standard_registry_matches_hand_maintained_nix_registry() {
        let source = fs::read_to_string(repo_root().join("nixos-modules/resources.nix"))
            .expect("resources.nix is readable");
        let start = source
            .find("standardResourceTypes = [")
            .expect("standardResourceTypes list is present");
        let rest = &source[start..];
        let end = rest
            .find("];")
            .expect("standardResourceTypes list terminates");
        let body = &rest[..end];
        let found: Vec<String> = body
            .lines()
            .skip(1)
            .filter_map(|line| {
                let trimmed = line.trim();
                trimmed
                    .strip_prefix('"')
                    .and_then(|rest| rest.strip_suffix('"'))
                    .map(str::to_owned)
            })
            .collect();
        assert_eq!(
            found,
            STANDARD_RESOURCE_TYPES
                .iter()
                .map(|name| (*name).to_owned())
                .collect::<Vec<String>>()
        );
    }

    #[test]
    fn provider_owned_u12_types_cannot_enter_the_core_registry() {
        assert!(
            STANDARD_RESOURCE_TYPES
                .iter()
                .all(|resource_type| !PROVIDER_OWNED_RESOURCE_TYPES.contains(resource_type))
        );
        let generated = generated_resource_types_module();
        for resource_type in PROVIDER_OWNED_RESOURCE_TYPES {
            assert!(!generated.contains(&format!("\"{resource_type}\"")));
        }
    }

    #[test]
    fn generated_artifacts_contain_no_non_ascii_dash() {
        let banned = [
            '\u{2010}', '\u{2011}', '\u{2012}', '\u{2013}', '\u{2014}', '\u{2015}', '\u{2212}',
            '\u{fe58}', '\u{ff0d}',
        ];
        let mut rendered = generated_resource_types_module();
        rendered.push_str(&generated_spec_canonical_module());
        for schema in &RESOURCE_TYPE_SCHEMAS {
            rendered.push_str(&generated_options_module(schema));
            rendered.push_str(
                &serde_json::to_string_pretty(&resource_schema(schema)).expect("schema renders"),
            );
        }
        for (_, schema) in standard_resource_schemas() {
            rendered.push_str(&serde_json::to_string_pretty(&schema).expect("schema renders"));
        }
        for character in banned {
            assert!(
                !rendered.contains(character),
                "generated artifacts must not contain U+{:04X}",
                character as u32
            );
        }
    }

    #[test]
    fn generation_is_deterministic() {
        for schema in &RESOURCE_TYPE_SCHEMAS {
            assert_eq!(
                generated_options_module(schema),
                generated_options_module(schema)
            );
        }
        assert_eq!(
            generated_spec_canonical_module(),
            generated_spec_canonical_module()
        );
    }

    #[test]
    fn standard_schema_artifacts_are_namespace_prefixed() {
        assert_eq!(
            core_schema_artifact_name("Credential"),
            "core.d2bus.org_Credential.schema.json"
        );
        assert_eq!(
            core_schema_artifact_name("ZoneLink"),
            "core.d2bus.org_ZoneLink.schema.json"
        );
    }

    #[test]
    fn generated_provider_and_transport_refs_are_schema_identified() {
        let credential = standard_resource_schemas()
            .into_iter()
            .find(|(name, _)| *name == "Credential")
            .map(|(_, schema)| schema)
            .expect("Credential schema");
        assert_eq!(
            credential["properties"]["spec"]["properties"]["providerRef"]["x-d2b-reference-kind"],
            json!("ResourceRef")
        );
        let zone_link = resource_schema(&RESOURCE_TYPE_SCHEMAS[1]);
        assert_eq!(
            zone_link["properties"]["spec"]["properties"]["transportProviderRef"]["x-d2b-allowed-ref-types"],
            json!(["Provider"])
        );
    }

    #[test]
    fn committed_artifacts_match_the_generator() {
        let root = repo_root();
        for (name, schema) in standard_resource_schemas() {
            let schema_path = root
                .join("docs/reference/schemas/v3")
                .join(core_schema_artifact_name(name));
            let mut expected = serde_json::to_string_pretty(&schema).expect("schema renders");
            expected.push('\n');
            let committed = fs::read_to_string(&schema_path)
                .unwrap_or_else(|_| panic!("{} is committed", schema_path.display()));
            assert_eq!(committed, expected, "{} drifted", schema_path.display());
        }
        for schema in &RESOURCE_TYPE_SCHEMAS {
            let schema_path = root
                .join("docs/reference/schemas/v3")
                .join(core_schema_artifact_name(schema.name));
            let mut expected =
                serde_json::to_string_pretty(&resource_schema(schema)).expect("schema renders");
            expected.push('\n');
            let committed = fs::read_to_string(&schema_path)
                .unwrap_or_else(|_| panic!("{} is committed", schema_path.display()));
            assert_eq!(committed, expected, "{} drifted", schema_path.display());

            let module_path = root.join(format!(
                "nixos-modules/generated/options-zones-{}.nix",
                schema.name
            ));
            let committed = fs::read_to_string(&module_path)
                .unwrap_or_else(|_| panic!("{} is committed", module_path.display()));
            assert_eq!(
                committed,
                generated_options_module(schema),
                "{} drifted",
                module_path.display()
            );
        }
        assert_eq!(
            fs::read_to_string(root.join("nixos-modules/generated/resource-types.nix"))
                .expect("resource-types.nix is committed"),
            generated_resource_types_module()
        );
        assert_eq!(
            fs::read_to_string(root.join("nixos-modules/generated/zone-spec-canonical.nix"))
                .expect("zone-spec-canonical.nix is committed"),
            generated_spec_canonical_module()
        );
    }
}
