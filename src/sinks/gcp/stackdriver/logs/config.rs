//! Configuration for the `gcp_stackdriver_logs` sink.

use std::collections::HashMap;

use http::{Request, Uri};
use hyper::Body;
use snafu::Snafu;
use vector_lib::{lookup::lookup_v2::ConfigValuePath, stream::BatcherSettings};
use vrl::value::Kind;

use super::{
    encoder::{
        ConfinedStackdriverLabelConfig, ConfinedStackdriverResource, StackdriverLogsEncoder,
    },
    request_builder::StackdriverLogsRequestBuilder,
    service::StackdriverLogsServiceRequestBuilder,
    sink::StackdriverLogsSink,
};
use crate::{
    gcp::{GcpAuthConfig, GcpAuthenticator, Scope},
    http::HttpClient,
    schema,
    sinks::{
        gcs_common::config::healthcheck_response,
        prelude::*,
        util::{
            BoxedRawValue, RealtimeSizeBasedDefaultBatchSettings,
            http::{HttpService, RetryStrategy, http_response_retry_logic},
            service::TowerRequestConfigDefaults,
        },
    },
    template::ConfinementConfig,
};

#[derive(Debug, Snafu)]
enum HealthcheckError {
    #[snafu(display("Resource not found"))]
    NotFound,
}

#[derive(Clone, Copy, Debug)]
pub struct StackdriverTowerRequestConfigDefaults;

impl TowerRequestConfigDefaults for StackdriverTowerRequestConfigDefaults {
    const RATE_LIMIT_NUM: u64 = 1_000;
}

/// Configuration for the `gcp_stackdriver_logs` sink.
#[configurable_component(sink(
    "gcp_stackdriver_logs",
    "Deliver logs to GCP's Cloud Operations suite."
))]
#[derive(Clone, Debug, Default)]
#[serde(deny_unknown_fields)]
pub(super) struct StackdriverConfig {
    #[serde(skip, default = "default_endpoint")]
    pub(super) endpoint: String,

    #[serde(flatten)]
    pub(super) log_name: StackdriverLogName,

    /// The log ID to which to publish logs.
    ///
    /// This is a name you create to identify this log stream.
    pub(super) log_id: Template,

    /// The monitored resource to associate the logs with.
    pub(super) resource: StackdriverResource,

    #[serde(flatten)]
    pub(super) label_config: StackdriverLabelConfig,

    /// The field of the log event from which to take the outgoing log’s `severity` field.
    ///
    /// The named field is removed from the log event if present, and must be either an integer
    /// between 0 and 800 or a string containing one of the [severity level names][sev_names] (case
    /// is ignored) or a common prefix such as `err`.
    ///
    /// If no severity key is specified, the severity of outgoing records is set to 0 (`DEFAULT`).
    ///
    /// See the [GCP Stackdriver Logging LogSeverity description][logsev_docs] for more details on
    /// the value of the `severity` field.
    ///
    /// [sev_names]: https://cloud.google.com/logging/docs/reference/v2/rest/v2/LogEntry#logseverity
    /// [logsev_docs]: https://cloud.google.com/logging/docs/reference/v2/rest/v2/LogEntry#logseverity
    #[configurable(metadata(docs::examples = "severity"))]
    pub(super) severity_key: Option<ConfigValuePath>,

    #[serde(flatten)]
    pub(super) auth: GcpAuthConfig,

    #[configurable(derived)]
    #[serde(default, skip_serializing_if = "crate::serde::is_default")]
    pub(super) encoding: Transformer,

    #[configurable(derived)]
    #[serde(default)]
    pub(super) batch: BatchConfig<RealtimeSizeBasedDefaultBatchSettings>,

    #[configurable(derived)]
    #[serde(default)]
    pub(super) request: TowerRequestConfig<StackdriverTowerRequestConfigDefaults>,

    #[configurable(derived)]
    pub(super) tls: Option<TlsConfig>,

    #[configurable(derived)]
    #[serde(
        default,
        deserialize_with = "crate::serde::bool_or_struct",
        skip_serializing_if = "crate::serde::is_default"
    )]
    acknowledgements: AcknowledgementsConfig,

    #[configurable(derived)]
    #[serde(default)]
    pub retry_strategy: RetryStrategy,

    #[configurable(derived)]
    #[serde(flatten)]
    pub confinement: ConfinementConfig,
}

pub(super) fn default_endpoint() -> String {
    "https://logging.googleapis.com/v2/entries:write".to_string()
}

// 10MB limit for entries.write: https://cloud.google.com/logging/quotas#api-limits
const MAX_BATCH_PAYLOAD_SIZE: usize = 10_000_000;

/// Logging locations.
#[configurable_component]
#[derive(Clone, Debug, Derivative)]
#[derivative(Default)]
pub(super) enum StackdriverLogName {
    /// The billing account ID to which to publish logs.
    ///
    ///	Exactly one of `billing_account_id`, `folder_id`, `organization_id`, or `project_id` must be set.
    #[serde(rename = "billing_account_id")]
    #[configurable(metadata(docs::examples = "012345-6789AB-CDEF01"))]
    BillingAccount(String),

    /// The folder ID to which to publish logs.
    ///
    /// See the [Google Cloud Platform folder documentation][folder_docs] for more details.
    ///
    ///	Exactly one of `billing_account_id`, `folder_id`, `organization_id`, or `project_id` must be set.
    ///
    /// [folder_docs]: https://cloud.google.com/resource-manager/docs/creating-managing-folders
    #[serde(rename = "folder_id")]
    #[configurable(metadata(docs::examples = "My Folder"))]
    Folder(String),

    /// The organization ID to which to publish logs.
    ///
    /// This would be the identifier assigned to your organization on Google Cloud Platform.
    ///
    ///	Exactly one of `billing_account_id`, `folder_id`, `organization_id`, or `project_id` must be set.
    #[serde(rename = "organization_id")]
    #[configurable(metadata(docs::examples = "622418129737"))]
    Organization(String),

    /// The project ID to which to publish logs.
    ///
    /// See the [Google Cloud Platform project management documentation][project_docs] for more details.
    ///
    ///	Exactly one of `billing_account_id`, `folder_id`, `organization_id`, or `project_id` must be set.
    ///
    /// [project_docs]: https://cloud.google.com/resource-manager/docs/creating-managing-projects
    #[derivative(Default)]
    #[serde(rename = "project_id")]
    #[configurable(metadata(docs::examples = "vector-123456"))]
    Project(String),
}

/// Label Configuration.
#[configurable_component]
#[derive(Clone, Debug, Default)]
pub(super) struct StackdriverLabelConfig {
    /// The value of this field is used to retrieve the associated labels from the `jsonPayload`
    /// and extract their values to set as LogEntry labels.
    #[configurable(metadata(docs::examples = "logging.googleapis.com/labels"))]
    #[serde(default = "default_labels_key")]
    pub(super) labels_key: Option<String>,

    /// A map of key, value pairs that provides additional information about the log entry.
    #[configurable(metadata(
        docs::additional_props_description = "A key, value pair that describes a log entry."
    ))]
    #[configurable(metadata(docs::examples = "labels_examples()"))]
    #[serde(default)]
    pub(super) labels: HashMap<String, Template>,
}

fn labels_examples() -> HashMap<String, String> {
    let mut example = HashMap::new();
    example.insert("label_1".to_string(), "value_1".to_string());
    example.insert("label_2".to_string(), "{{ template_value_2 }}".to_string());
    example
}

pub(super) fn default_labels_key() -> Option<String> {
    Some("logging.googleapis.com/labels".to_string())
}

/// A monitored resource.
///
/// Monitored resources in GCP allow associating logs and metrics specifically with native resources
/// within Google Cloud Platform. This takes the form of a "type" field which identifies the
/// resource, and a set of type-specific labels to uniquely identify a resource of that type.
///
/// See [Monitored resource types][mon_docs] for more information.
///
/// [mon_docs]: https://cloud.google.com/monitoring/api/resources
// TODO: this type is specific to the stackdrivers log sink because it allows for template-able
// label values, but we should consider replacing `sinks::gcp::GcpTypedResource` with this so both
// the stackdriver metrics _and_ logs sink can have template-able label values, and less duplication
#[configurable_component]
#[derive(Clone, Debug, Default)]
pub(super) struct StackdriverResource {
    /// The monitored resource type.
    ///
    /// For example, the type of a Compute Engine VM instance is `gce_instance`.
    /// See the [Google Cloud Platform monitored resource documentation][gcp_resources] for
    /// more details.
    ///
    /// [gcp_resources]: https://cloud.google.com/monitoring/api/resources
    #[serde(rename = "type")]
    pub(super) type_: String,

    /// Type-specific labels.
    #[serde(flatten)]
    #[configurable(metadata(docs::additional_props_description = "A type-specific label."))]
    #[configurable(metadata(docs::examples = "label_examples()"))]
    pub(super) labels: HashMap<String, Template>,
}

fn label_examples() -> HashMap<String, String> {
    let mut example = HashMap::new();
    example.insert("instanceId".to_string(), "Twilight".to_string());
    example.insert("zone".to_string(), "{{ zone }}".to_string());
    example
}

impl_generate_config_from_default!(StackdriverConfig);

/// Values derived while validating [`StackdriverConfig`], consumed by its `build`.
///
/// The fields are private, so the only way to obtain the confined templates the sink renders with
/// is [`ValidateSink::validate`].
#[derive(Debug)]
pub struct ValidatedStackdriverLogs {
    log_id: ConfinedTemplate,
    resource: ConfinedStackdriverResource,
    label_config: ConfinedStackdriverLabelConfig,
    batch_settings: BatcherSettings,
}

impl ValidateSink for StackdriverConfig {
    type Validated = ValidatedStackdriverLogs;

    fn validate(&self) -> std::result::Result<Self::Validated, Vec<String>> {
        let mut errors = Vec::new();

        let batch_settings = self
            .batch
            .validate()
            .and_then(|b| b.limit_max_bytes(MAX_BATCH_PAYLOAD_SIZE))
            .and_then(|b| b.into_batcher_settings())
            .inspect_err(|e| errors.push(format!("batch: {e}")))
            .ok();

        let log_id = self
            .log_id
            .clone()
            .confine(&self.confinement, Self::NAME, "log_id")
            .inspect_err(|e| errors.push(e.to_string()))
            .ok();

        // Confine every label value template. Stackdriver identifies
        // destinations by `resource.type + resource.labels`, so an event-
        // controlled label like `resource.labels.zone: "{{ zone }}"` is as
        // steerable as `log_id` unless we confine it too. Same for arbitrary
        // log-entry labels in `label_config.labels`.
        let mut resource_labels = HashMap::with_capacity(self.resource.labels.len());
        let mut resource_labels_valid = true;
        for (k, v) in self.resource.labels.clone() {
            let label = v
                .confine(&self.confinement, Self::NAME, "resource.labels")
                .inspect_err(|e| errors.push(format!("resource.labels.{}: {}", k, e)))
                .ok();
            match label {
                Some(v) => {
                    resource_labels.insert(k, v);
                }
                None => {
                    resource_labels_valid = false;
                }
            }
        }
        let resource = resource_labels_valid.then(|| ConfinedStackdriverResource {
            type_: self.resource.type_.clone(),
            labels: resource_labels,
        });

        let mut labels = HashMap::with_capacity(self.label_config.labels.len());
        let mut labels_valid = true;
        for (k, v) in self.label_config.labels.clone() {
            let label = v
                .confine(&self.confinement, Self::NAME, "label_config.labels")
                .inspect_err(|e| errors.push(format!("labels.{}: {}", k, e)))
                .ok();
            match label {
                Some(v) => {
                    labels.insert(k, v);
                }
                None => {
                    labels_valid = false;
                }
            }
        }
        let label_config = labels_valid.then(|| ConfinedStackdriverLabelConfig {
            labels_key: self.label_config.labels_key.clone(),
            labels,
        });

        match (
            errors.is_empty(),
            batch_settings,
            log_id,
            resource,
            label_config,
        ) {
            (true, Some(batch_settings), Some(log_id), Some(resource), Some(label_config)) => {
                Ok(ValidatedStackdriverLogs {
                    log_id,
                    resource,
                    label_config,
                    batch_settings,
                })
            }
            _ => Err(errors),
        }
    }
}

#[async_trait::async_trait]
#[typetag::serde(name = "gcp_stackdriver_logs")]
impl SinkConfig for StackdriverConfig {
    fn validate_structure(&self) -> std::result::Result<(), Vec<String>> {
        self.validate().map(|_| ())
    }

    async fn build(&self, cx: SinkContext) -> crate::Result<(VectorSink, Healthcheck)> {
        let ValidatedStackdriverLogs {
            log_id,
            resource,
            label_config,
            batch_settings,
        } = self.validate().map_err(|errors| errors.join("; "))?;

        let auth = self.auth.build(Scope::LoggingWrite).await?;

        let request_builder = StackdriverLogsRequestBuilder {
            encoder: StackdriverLogsEncoder::new(
                self.encoding.clone(),
                log_id,
                self.log_name.clone(),
                label_config,
                resource,
                self.severity_key.clone(),
            ),
        };

        let request_limits = self.request.into_settings();

        let tls_settings = TlsSettings::from_options(self.tls.as_ref())?;
        let client = HttpClient::new(tls_settings, cx.proxy())?;

        let uri: Uri = self.endpoint.parse()?;

        let stackdriver_logs_service_request_builder = StackdriverLogsServiceRequestBuilder {
            uri: uri.clone(),
            auth: auth.clone(),
        };

        let service = HttpService::new(client.clone(), stackdriver_logs_service_request_builder);

        let service = ServiceBuilder::new()
            .settings(
                request_limits,
                http_response_retry_logic(self.retry_strategy.clone()),
            )
            .service(service);

        let sink = StackdriverLogsSink::new(service, batch_settings, request_builder);

        let healthcheck = healthcheck(client, auth.clone(), uri).boxed();

        auth.spawn_regenerate_token();
        Ok((VectorSink::from_event_streamsink(sink), healthcheck))
    }

    fn confinement_config(&self) -> Option<&crate::template::ConfinementConfig> {
        Some(&self.confinement)
    }

    fn input(&self) -> Input {
        let requirement =
            schema::Requirement::empty().required_meaning("timestamp", Kind::timestamp());

        Input::log().with_schema_requirement(requirement)
    }

    fn acknowledgements(&self) -> &AcknowledgementsConfig {
        &self.acknowledgements
    }
}

async fn healthcheck(client: HttpClient, auth: GcpAuthenticator, uri: Uri) -> crate::Result<()> {
    let entries: Vec<BoxedRawValue> = Vec::new();
    let events = serde_json::json!({ "entries": entries });

    let body = crate::serde::json::to_bytes(&events).unwrap().freeze();

    let mut request = Request::post(uri)
        .header("Content-Type", "application/json")
        .body(body)
        .unwrap();

    auth.apply(&mut request);

    let request = request.map(Body::from);

    let response = client.send(request).await?;

    healthcheck_response(response, HealthcheckError::NotFound.into())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use vrl::event_path;

    use super::*;
    use crate::{
        config::ValidateSink,
        event::{Event, LogEvent},
        template::{ConfinementConfig, Template},
    };

    #[test]
    fn confinement_rejects_unconfined_log_id() {
        let template = Template::try_from("{{ log_id }}").unwrap();
        let config = ConfinementConfig::default();
        let result = template.confine(&config, "gcp_stackdriver_logs", "log_id");
        assert!(result.is_err());
    }

    #[test]
    fn confinement_opt_out_allows_unconfined_log_id() {
        let template = Template::try_from("{{ log_id }}").unwrap();
        let config = ConfinementConfig {
            dangerously_allow_unconfined_template_resolution: true,
        };
        let result = template.confine(&config, "gcp_stackdriver_logs", "log_id");
        assert!(result.is_ok());
    }

    #[test]
    fn confinement_allows_prefixed_log_id() {
        let template = Template::try_from("events-{{ env }}").unwrap();
        let config = ConfinementConfig::default();
        let result = template.confine(&config, "gcp_stackdriver_logs", "log_id");
        assert!(result.is_ok());
    }

    #[test]
    fn validate_yields_confined_templates() {
        let config = StackdriverConfig {
            log_id: Template::try_from("events-{{ env }}").unwrap(),
            resource: StackdriverResource {
                type_: "generic_node".to_string(),
                labels: HashMap::from([(
                    "zone".to_string(),
                    Template::try_from("zone-{{ env }}").unwrap(),
                )]),
            },
            label_config: StackdriverLabelConfig {
                labels_key: None,
                labels: HashMap::from([(
                    "label".to_string(),
                    Template::try_from("label-{{ env }}").unwrap(),
                )]),
            },
            ..Default::default()
        };

        let validated = config.validate().expect("config is valid");

        let mut event = LogEvent::from("message");
        event.insert(event_path!("env"), "prod");
        let event = Event::from(event);

        assert_eq!(
            validated.log_id.render_string(&event).unwrap(),
            "events-prod"
        );
        assert_eq!(
            validated.resource.labels["zone"]
                .render_string(&event)
                .unwrap(),
            "zone-prod"
        );
        assert_eq!(
            validated.label_config.labels["label"]
                .render_string(&event)
                .unwrap(),
            "label-prod"
        );
    }
}
