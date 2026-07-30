use std::collections::HashMap;

use vrl::value::Kind;

use super::{healthcheck::healthcheck, sink::LokiSink};
use crate::{
    http::{Auth, HttpClient, MaybeAuth},
    schema,
    sinks::{prelude::*, util::UriSerde},
    template::{ConfinementConfig, Template},
};

const fn default_compression() -> Compression {
    Compression::Snappy
}

fn default_loki_path() -> String {
    "/loki/api/v1/push".to_string()
}

/// Configuration for the `loki` sink.
#[configurable_component(sink("loki", "Deliver log event data to the Loki aggregation system."))]
#[derive(Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct LokiConfig {
    /// The base URL of the Loki instance.
    ///
    /// The `path` value is appended to this.
    #[configurable(metadata(docs::examples = "http://localhost:3100"))]
    pub endpoint: UriSerde,

    /// The path to use in the URL of the Loki instance.
    #[serde(default = "default_loki_path")]
    pub path: String,

    #[configurable(derived)]
    pub encoding: EncodingConfig,

    /// The [tenant ID][tenant_id] to specify in requests to Loki.
    ///
    /// When running Loki locally, a tenant ID is not required.
    ///
    /// [tenant_id]: https://grafana.com/docs/loki/latest/operations/multi-tenancy/
    #[configurable(metadata(
        docs::examples = "some_tenant_id",
        docs::examples = "{{ event_field }}",
    ))]
    pub tenant_id: Option<Template>,

    /// A set of labels that are attached to each batch of events.
    ///
    /// Both keys and values are templateable, which enables you to attach dynamic labels to events.
    ///
    /// Valid label keys include `*`, and prefixes ending with `*`, to allow for the expansion of
    /// objects into multiple labels. See [Label expansion][label_expansion] for more information.
    ///
    /// Note: If the set of labels has high cardinality, this can cause drastic performance issues
    /// with Loki. To prevent this from happening, reduce the number of unique label keys and
    /// values.
    ///
    /// [label_expansion]: https://vector.dev/docs/reference/configuration/sinks/loki/#label-expansion
    #[configurable(metadata(docs::examples = "loki_labels_examples()"))]
    #[configurable(metadata(docs::additional_props_description = "A Loki label."))]
    #[configurable(metadata(docs::required = true))]
    pub labels: HashMap<Template, Template>,

    /// Whether or not to delete fields from the event when they are used as labels.
    #[serde(default = "crate::serde::default_false")]
    pub remove_label_fields: bool,

    /// Structured metadata that is attached to each batch of events.
    ///
    /// Both keys and values are templateable, which enables you to attach dynamic structured metadata to events.
    ///
    /// Valid metadata keys include `*`, and prefixes ending with `*`, to allow for the expansion of
    /// objects into multiple metadata entries. This follows the same logic as [Label expansion][label_expansion].
    ///
    /// [label_expansion]: https://vector.dev/docs/reference/configuration/sinks/loki/#label-expansion
    #[configurable(metadata(docs::examples = "loki_structured_metadata_examples()"))]
    #[configurable(metadata(docs::additional_props_description = "Loki structured metadata."))]
    #[serde(default)]
    pub structured_metadata: HashMap<Template, Template>,

    /// Whether or not to delete fields from the event when they are used in structured metadata.
    #[serde(default = "crate::serde::default_false")]
    pub remove_structured_metadata_fields: bool,

    /// Whether or not to remove the timestamp from the event payload.
    ///
    /// The timestamp is still sent as event metadata for Loki to use for indexing.
    #[serde(default = "crate::serde::default_true")]
    pub remove_timestamp: bool,

    /// Compression configuration.
    /// Snappy compression implies sending push requests as Protocol Buffers.
    #[serde(default = "default_compression")]
    pub compression: Compression,

    #[configurable(derived)]
    #[serde(default)]
    pub out_of_order_action: OutOfOrderAction,

    #[configurable(derived)]
    pub auth: Option<Auth>,

    #[configurable(derived)]
    #[serde(default)]
    pub request: TowerRequestConfig,

    #[configurable(derived)]
    #[serde(default)]
    pub batch: BatchConfig<LokiDefaultBatchSettings>,

    #[configurable(derived)]
    pub tls: Option<TlsConfig>,

    #[configurable(derived)]
    #[serde(
        default,
        deserialize_with = "crate::serde::bool_or_struct",
        skip_serializing_if = "crate::serde::is_default"
    )]
    acknowledgements: AcknowledgementsConfig,

    #[configurable(derived)]
    #[serde(flatten)]
    pub confinement: ConfinementConfig,
}

fn loki_labels_examples() -> HashMap<String, String> {
    let mut examples = HashMap::new();
    examples.insert("source".to_string(), "vector".to_string());
    examples.insert(
        "\"pod_labels_*\"".to_string(),
        "{{ kubernetes.pod_labels }}".to_string(),
    );
    examples.insert("\"*\"".to_string(), "{{ metadata }}".to_string());
    examples.insert(
        "{{ event_field }}".to_string(),
        "{{ some_other_event_field }}".to_string(),
    );
    examples
}

fn loki_structured_metadata_examples() -> HashMap<String, String> {
    let mut examples = HashMap::new();
    examples.insert("source".to_string(), "vector".to_string());
    examples.insert(
        "\"pod_labels_*\"".to_string(),
        "{{ kubernetes.pod_labels }}".to_string(),
    );
    examples.insert("\"*\"".to_string(), "{{ metadata }}".to_string());
    examples.insert(
        "{{ event_field }}".to_string(),
        "{{ some_other_event_field }}".to_string(),
    );
    examples
}

#[derive(Clone, Copy, Debug, Default)]
pub struct LokiDefaultBatchSettings;

impl SinkBatchSettings for LokiDefaultBatchSettings {
    const MAX_EVENTS: Option<usize> = Some(100_000);
    const MAX_BYTES: Option<usize> = Some(1_000_000);
    const TIMEOUT_SECS: f64 = 1.0;
}

/// Out-of-order event behavior.
///
/// Some sources may generate events with timestamps that aren't in chronological order. Even though the
/// sink sorts the events before sending them to Loki, there is a chance that another event could come in
/// that is out of order with the latest events sent to Loki. Prior to Loki 2.4.0, this
/// was not supported and would result in an error during the push request.
///
/// If you're using Loki 2.4.0 or newer, `Accept` is the preferred action, which lets Loki handle
/// any necessary sorting/reordering. If you're using an earlier version, then you must use `Drop`
/// or `RewriteTimestamp` depending on which option makes the most sense for your use case.
#[configurable_component]
#[derive(Copy, Clone, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub enum OutOfOrderAction {
    /// Accept the event.
    ///
    /// The event is not dropped and is sent without modification.
    ///
    /// Requires Loki 2.4.0 or newer.
    #[default]
    Accept,

    /// Rewrite the timestamp of the event to the timestamp of the latest event seen by the sink.
    RewriteTimestamp,

    /// Drop the event.
    Drop,
}

impl GenerateConfig for LokiConfig {
    fn generate_config() -> serde_json::Value {
        toml::from_str(
            r#"endpoint = "http://localhost:3100"
            encoding.codec = "json"
            labels = {}"#,
        )
        .unwrap()
    }
}

impl LokiConfig {
    pub(super) fn build_client(&self, cx: SinkContext) -> crate::Result<HttpClient> {
        let tls = TlsSettings::from_options(self.tls.as_ref())?;
        let client = HttpClient::new(tls, cx.proxy())?;
        Ok(client)
    }
}

fn confine_template_map(
    map: &HashMap<Template, Template>,
    config: &ConfinementConfig,
    component_name: &'static str,
    key_field_name: &'static str,
    value_field_name: &'static str,
    errors: &mut Vec<String>,
) -> Option<HashMap<ConfinedTemplate, ConfinedTemplate>> {
    let mut confined = HashMap::with_capacity(map.len());
    let mut valid = true;

    for (k, v) in map {
        let key = k
            .clone()
            .confine(config, component_name, key_field_name)
            .inspect_err(|e| errors.push(e.to_string()))
            .ok();
        let value = v
            .clone()
            .confine(config, component_name, value_field_name)
            .inspect_err(|e| errors.push(e.to_string()))
            .ok();

        match (key, value) {
            (Some(key), Some(value)) => {
                confined.insert(key, value);
            }
            _ => valid = false,
        }
    }

    valid.then_some(confined)
}

/// Values derived while validating [`LokiConfig`], consumed by its `build`.
///
/// The fields are private, so the only way to obtain the selected auth, confined templates,
/// batcher settings, and protocol the sink uses is [`ValidateSink::validate`].
#[derive(Debug)]
pub struct ValidatedLokiSink {
    auth: Option<Auth>,
    protocol: &'static str,
    tenant_id: Option<ConfinedTemplate>,
    labels: HashMap<ConfinedTemplate, ConfinedTemplate>,
    structured_metadata: HashMap<ConfinedTemplate, ConfinedTemplate>,
    batch_settings: BatcherSettings,
}

impl ValidateSink for LokiConfig {
    type Validated = ValidatedLokiSink;

    fn validate(&self) -> std::result::Result<Self::Validated, Vec<String>> {
        let mut errors = Vec::new();

        let auth = self
            .auth
            .choose_one(&self.endpoint.auth)
            .inspect_err(|_| {
                errors.push(
                    "Both `auth` and credentials in `endpoint` URL are set. Only one can be used."
                        .to_string(),
                );
            })
            .ok();

        let scheme = self.endpoint.uri.scheme().map(|s| s.as_str()).unwrap_or("");
        let protocol = match scheme {
            "http" => Some("http"),
            "https" => Some("https"),
            _ => {
                errors.push(format!(
                    "endpoint: scheme must be 'http' or 'https', got '{}'",
                    scheme
                ));
                None
            }
        };

        if self.labels.is_empty() {
            errors.push("`labels` must include at least one label.".to_string());
        }

        for label in self.labels.keys() {
            if !valid_label_name(label) {
                errors.push(format!("Invalid label name {:?}", label.get_ref()));
            }
        }

        let tenant_id = self
            .tenant_id
            .clone()
            .map(|template| template.confine(&self.confinement, Self::NAME, "tenant_id"))
            .transpose()
            .inspect_err(|e| errors.push(e.to_string()))
            .ok();

        let labels = confine_template_map(
            &self.labels,
            &self.confinement,
            Self::NAME,
            "labels[key]",
            "labels[value]",
            &mut errors,
        );
        let structured_metadata = confine_template_map(
            &self.structured_metadata,
            &self.confinement,
            Self::NAME,
            "structured_metadata[key]",
            "structured_metadata[value]",
            &mut errors,
        );

        let batch_settings = self
            .batch
            .into_batcher_settings()
            .inspect_err(|e| errors.push(format!("batch: {e}")))
            .ok();

        // Validate encoding configuration (structural checks only, no I/O)
        // This checks message_type format for Protobuf without reading the descriptor file.
        if let Err(e) = self.encoding.validate_structure() {
            errors.push(format!("encoding: {e}"));
        }

        match (
            errors.is_empty(),
            auth,
            protocol,
            tenant_id,
            labels,
            structured_metadata,
            batch_settings,
        ) {
            (
                true,
                Some(auth),
                Some(protocol),
                Some(tenant_id),
                Some(labels),
                Some(structured_metadata),
                Some(batch_settings),
            ) => Ok(ValidatedLokiSink {
                auth,
                protocol,
                tenant_id,
                labels,
                structured_metadata,
                batch_settings,
            }),
            _ => Err(errors),
        }
    }
}

impl ValidatedLokiSink {
    pub(super) fn into_sink_parts(
        self,
    ) -> (
        Option<ConfinedTemplate>,
        HashMap<ConfinedTemplate, ConfinedTemplate>,
        HashMap<ConfinedTemplate, ConfinedTemplate>,
        BatcherSettings,
        &'static str,
    ) {
        (
            self.tenant_id,
            self.labels,
            self.structured_metadata,
            self.batch_settings,
            self.protocol,
        )
    }
}

#[async_trait::async_trait]
#[typetag::serde(name = "loki")]
impl SinkConfig for LokiConfig {
    fn validate_structure(&self) -> std::result::Result<(), Vec<String>> {
        self.validate().map(|_| ())
    }

    async fn build(
        &self,
        cx: SinkContext,
    ) -> crate::Result<(VectorSink, crate::sinks::Healthcheck)> {
        let validated = self.validate().map_err(|errors| errors.join("; "))?;
        let client = self.build_client(cx)?;

        let config = LokiConfig {
            auth: validated.auth.clone(),
            ..self.clone()
        };

        let sink = LokiSink::new(config.clone(), client.clone(), validated)?;

        let healthcheck = healthcheck(config, client).boxed();
        Ok((VectorSink::from_event_streamsink(sink), healthcheck))
    }

    fn confinement_config(&self) -> Option<&crate::template::ConfinementConfig> {
        Some(&self.confinement)
    }

    fn input(&self) -> Input {
        let requirement =
            schema::Requirement::empty().optional_meaning("timestamp", Kind::timestamp());

        Input::new(self.encoding.config().input_type() & DataType::Log)
            .with_schema_requirement(requirement)
    }

    fn acknowledgements(&self) -> &AcknowledgementsConfig {
        &self.acknowledgements
    }
}

pub fn valid_label_name(label: &Template) -> bool {
    label.is_dynamic() || {
        // Loki follows prometheus on this https://prometheus.io/docs/concepts/data_model/#metric-names-and-labels
        // Although that isn't explicitly said anywhere besides what's in the code.
        // The closest mention is in section about Parser Expression https://grafana.com/docs/loki/latest/logql/
        //
        // [a-zA-Z_][a-zA-Z0-9_]*
        //
        // '*' symbol at the end of the label name will be treated as a prefix for
        // underlying object keys.
        let mut label_trim = label.get_ref().trim();
        if let Some(without_opening_end) = label_trim.strip_suffix('*') {
            label_trim = without_opening_end
        }

        let mut label_chars = label_trim.chars();
        if let Some(ch) = label_chars.next() {
            (ch.is_ascii_alphabetic() || ch == '_')
                && label_chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
        } else {
            label.get_ref().trim() == "*"
        }
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryInto;

    use super::{LokiConfig, valid_label_name};
    use crate::template::{ConfinementConfig, Template};

    #[test]
    fn valid_label_names() {
        assert!(valid_label_name(&"name".try_into().unwrap()));
        assert!(valid_label_name(&" name ".try_into().unwrap()));
        assert!(valid_label_name(&"bee_bop".try_into().unwrap()));
        assert!(valid_label_name(&"a09b".try_into().unwrap()));
        assert!(valid_label_name(&"abc_*".try_into().unwrap()));
        assert!(valid_label_name(&"_*".try_into().unwrap()));
        assert!(valid_label_name(&"*".try_into().unwrap()));

        assert!(!valid_label_name(&"0ab".try_into().unwrap()));
        assert!(!valid_label_name(&"".try_into().unwrap()));
        assert!(!valid_label_name(&" ".try_into().unwrap()));

        assert!(valid_label_name(&"{{field}}".try_into().unwrap()));
    }

    #[test]
    fn confinement_rejects_unconfined_tenant_id() {
        let template = Template::try_from("{{ tenant }}").unwrap();
        let config = ConfinementConfig::default();
        let result = template.confine(&config, "loki", "tenant_id");
        assert!(
            result.is_err(),
            "bare tenant_id template with no literal prefix must be rejected"
        );
    }

    #[test]
    fn confinement_opt_out_allows_unconfined_tenant_id() {
        let template = Template::try_from("{{ tenant }}").unwrap();
        let config = ConfinementConfig {
            dangerously_allow_unconfined_template_resolution: true,
        };
        let result = template.confine(&config, "loki", "tenant_id");
        assert!(result.is_ok(), "opt-out must allow bare tenant_id template");
    }

    #[test]
    fn confinement_prefixed_tenant_id_locks_org_prefix() {
        use crate::event::{Event, LogEvent};
        use vrl::event_path;
        // "team-{{ org }}" has literal prefix "team-"; an attacker controlling `org`
        // cannot steer the rendered value to an org outside the "team-" namespace.
        let template = Template::try_from("team-{{ org }}").unwrap();
        let config = ConfinementConfig::default();
        let confined = template.confine(&config, "loki", "tenant_id").unwrap();
        let mut event = LogEvent::default();
        event.insert(event_path!("org"), "other-tenant-entirely");
        let rendered = confined.render_string(&Event::Log(event)).unwrap();
        assert!(
            rendered.starts_with("team-"),
            "operator-controlled prefix must be preserved in rendered tenant_id"
        );
    }

    #[test]
    fn validate_yields_confined_templates() {
        use std::collections::HashMap;

        use crate::{
            config::ValidateSink,
            event::{Event, LogEvent},
        };
        use vrl::event_path;

        let mut labels = HashMap::new();
        labels.insert(
            Template::try_from("label_{{ label }}").unwrap(),
            Template::try_from("value_{{ value }}").unwrap(),
        );

        let mut structured_metadata = HashMap::new();
        structured_metadata.insert(
            Template::try_from("metadata_{{ metadata_key }}").unwrap(),
            Template::try_from("metadata_value_{{ metadata_value }}").unwrap(),
        );

        let config = LokiConfig {
            tenant_id: Some(Template::try_from("tenant-{{ tenant }}").unwrap()),
            labels,
            structured_metadata,
            ..toml::from_str::<LokiConfig>(
                r#"
endpoint = "http://localhost:3100"
encoding.codec = "text"
labels = {"static_label" = "static_value"}
"#,
            )
            .unwrap()
        };

        let validated = config.validate().expect("config is valid");

        let mut event = LogEvent::default();
        event.insert(event_path!("tenant"), "team");
        event.insert(event_path!("label"), "env");
        event.insert(event_path!("value"), "prod");
        event.insert(event_path!("metadata_key"), "source");
        event.insert(event_path!("metadata_value"), "vector");
        let event = Event::from(event);

        assert_eq!(
            validated
                .tenant_id
                .as_ref()
                .unwrap()
                .render_string(&event)
                .unwrap(),
            "tenant-team"
        );

        let rendered_labels = validated
            .labels
            .iter()
            .map(|(key, value)| {
                (
                    key.render_string(&event).unwrap(),
                    value.render_string(&event).unwrap(),
                )
            })
            .collect::<HashMap<_, _>>();
        assert_eq!(rendered_labels["label_env"].as_str(), "value_prod");

        let rendered_metadata = validated
            .structured_metadata
            .iter()
            .map(|(key, value)| {
                (
                    key.render_string(&event).unwrap(),
                    value.render_string(&event).unwrap(),
                )
            })
            .collect::<HashMap<_, _>>();
        assert_eq!(
            rendered_metadata["metadata_source"].as_str(),
            "metadata_value_vector"
        );
    }

    #[test]
    fn validate_structure_rejects_empty_labels() {
        use super::LokiConfig;
        use crate::config::SinkConfig;
        use crate::sinks::util::UriSerde;
        use std::collections::HashMap;
        use vector_lib::codecs::TextSerializerConfig;

        let config = LokiConfig {
            endpoint: "http://localhost:3100".parse::<UriSerde>().unwrap(),
            labels: HashMap::new(),
            encoding: TextSerializerConfig::default().into(),
            ..toml::from_str::<LokiConfig>(
                r#"
endpoint = "http://localhost:3100"
encoding.codec = "text"
labels = {"static_label" = "static_value"}
"#,
            )
            .unwrap()
        };

        let errors = config.validate_structure().unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| e.contains("labels") && e.contains("at least one")),
            "unexpected errors: {:?}",
            errors
        );
    }

    #[test]
    fn validate_structure_rejects_invalid_label_name() {
        use super::LokiConfig;
        use crate::config::SinkConfig;
        use std::collections::HashMap;

        let mut labels = HashMap::new();
        labels.insert(
            Template::try_from("bad-label").unwrap(),
            Template::try_from("value").unwrap(),
        );

        let label_config = toml::from_str::<LokiConfig>(
            r#"
endpoint = "http://localhost:3100"
encoding.codec = "text"
labels = {"static_label" = "static_value"}
"#,
        )
        .unwrap();

        let config = LokiConfig {
            labels,
            ..label_config
        };

        let errors = config.validate_structure().unwrap_err();
        assert!(
            errors.iter().any(|e| e.contains("Invalid label name")),
            "unexpected errors: {:?}",
            errors
        );
    }

    #[test]
    fn validate_structure_rejects_duplicate_credentials() {
        use super::LokiConfig;
        use crate::config::SinkConfig;
        use crate::http::Auth;
        use crate::sinks::util::UriSerde;

        let label_config = toml::from_str::<LokiConfig>(
            r#"
endpoint = "http://localhost:3100"
encoding.codec = "text"
labels = {"static_label" = "static_value"}
"#,
        )
        .unwrap();

        let config = LokiConfig {
            endpoint: "http://user:pass@localhost:3100"
                .parse::<UriSerde>()
                .unwrap(),
            auth: Some(Auth::Basic {
                user: "otheruser".to_string(),
                password: "otherpass".to_string().into(),
            }),
            ..label_config
        };

        let errors = config.validate_structure().unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| e.contains("auth") && e.contains("endpoint")),
            "unexpected errors: {:?}",
            errors
        );
    }
}
