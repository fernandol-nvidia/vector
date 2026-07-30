use std::{collections::BTreeMap, fmt, sync::Arc};

#[cfg(feature = "aws-core")]
use aws_types::region::Region;
use http::{HeaderValue, Uri, header::AUTHORIZATION};

#[cfg(feature = "aws-core")]
use super::Errors;
use super::{
    service::{RemoteWriteService, build_request},
    sink::{PrometheusRemoteWriteDefaultBatchSettings, RemoteWriteSink},
};
use crate::{
    http::HttpClient,
    sinks::{
        prelude::*,
        prometheus::PrometheusRemoteWriteAuth,
        util::{
            auth::Auth,
            http::{OrderedHeaderName, RetryStrategy, http_response_retry_logic},
            service::TowerRequestConfig,
        },
    },
    template::ConfinementConfig,
};

/// The batch config for remote write.
#[configurable_component]
#[derive(Clone, Copy, Debug, Derivative)]
#[derivative(Default)]
pub struct RemoteWriteBatchConfig {
    #[configurable(derived)]
    #[serde(flatten)]
    pub batch_settings: BatchConfig<PrometheusRemoteWriteDefaultBatchSettings>,

    /// Whether or not to aggregate metrics within a batch.
    #[serde(default = "crate::serde::default_true")]
    #[derivative(Default(value = "true"))]
    pub aggregate: bool,
}

/// Configuration for the `prometheus_remote_write` sink.
#[configurable_component(sink(
    "prometheus_remote_write",
    "Deliver metric data to a Prometheus remote write endpoint."
))]
#[derive(Clone, Debug, Derivative)]
#[derivative(Default)]
#[serde(deny_unknown_fields)]
pub struct RemoteWriteConfig {
    /// The endpoint to send data to.
    ///
    /// The endpoint should include the scheme and the path to write to.
    #[configurable(metadata(docs::examples = "https://localhost:8087/api/v1/write"))]
    pub endpoint: String,

    /// The default namespace for any metrics sent.
    ///
    /// This namespace is only used if a metric has no existing namespace. When a namespace is
    /// present, it is used as a prefix to the metric name, and separated with an underscore (`_`).
    ///
    /// It should follow the Prometheus [naming conventions][prom_naming_docs].
    ///
    /// [prom_naming_docs]: https://prometheus.io/docs/practices/naming/#metric-names
    #[configurable(metadata(docs::examples = "service"))]
    #[configurable(metadata(docs::advanced))]
    pub default_namespace: Option<String>,

    /// Default buckets to use for aggregating [distribution][dist_metric_docs] metrics into histograms.
    ///
    /// [dist_metric_docs]: https://vector.dev/docs/architecture/data-model/metric/#distribution
    #[serde(default = "crate::sinks::prometheus::default_histogram_buckets")]
    #[configurable(metadata(docs::advanced))]
    pub buckets: Vec<f64>,

    /// Quantiles to use for aggregating [distribution][dist_metric_docs] metrics into a summary.
    ///
    /// [dist_metric_docs]: https://vector.dev/docs/architecture/data-model/metric/#distribution
    #[serde(default = "crate::sinks::prometheus::default_summary_quantiles")]
    #[configurable(metadata(docs::advanced))]
    pub quantiles: Vec<f64>,

    #[configurable(derived)]
    #[serde(default)]
    pub batch: RemoteWriteBatchConfig,

    #[configurable(derived)]
    #[serde(default)]
    pub request: RemoteWriteRequestConfig,

    /// The tenant ID to send.
    ///
    /// If set, a header named `X-Scope-OrgID` is added to outgoing requests with the value of this setting.
    ///
    /// This may be used by Cortex or other remote services to identify the tenant making the request.
    #[serde(default)]
    #[configurable(metadata(docs::examples = "my-domain"))]
    #[configurable(metadata(docs::advanced))]
    pub tenant_id: Option<Template>,

    /// The amount of time, in seconds, that incremental metrics will persist in the internal metrics cache
    /// after having not been updated before they expire and are removed.
    ///
    /// If unset, sending unique incremental metrics to this sink will cause indefinite memory growth.
    #[serde(skip_serializing_if = "crate::serde::is_default")]
    #[configurable(metadata(docs::common = false, docs::required = false))]
    pub expire_metrics_secs: Option<f64>,

    #[configurable(derived)]
    pub tls: Option<TlsConfig>,

    #[configurable(derived)]
    pub auth: Option<PrometheusRemoteWriteAuth>,

    #[cfg(feature = "aws-config")]
    #[configurable(derived)]
    #[configurable(metadata(docs::advanced))]
    pub aws: Option<crate::aws::RegionOrEndpoint>,

    #[configurable(derived)]
    #[serde(
        default,
        deserialize_with = "crate::serde::bool_or_struct",
        skip_serializing_if = "crate::serde::is_default"
    )]
    pub acknowledgements: AcknowledgementsConfig,

    #[configurable(derived)]
    #[configurable(metadata(docs::advanced))]
    #[serde(default = "default_compression")]
    #[derivative(Default(value = "default_compression()"))]
    pub compression: Compression,

    #[configurable(derived)]
    #[serde(default)]
    pub retry_strategy: RetryStrategy,

    #[configurable(derived)]
    #[serde(flatten)]
    pub confinement: ConfinementConfig,
}

const fn default_compression() -> Compression {
    Compression::Snappy
}

impl_generate_config_from_default!(RemoteWriteConfig);

/// Outbound HTTP request settings for the Prometheus remote write sink.
#[configurable_component]
#[derive(Clone, Debug, Default)]
#[serde(default)]
pub struct RemoteWriteRequestConfig {
    #[serde(flatten)]
    pub tower: TowerRequestConfig,

    /// Additional HTTP headers to add to every HTTP request.
    ///
    /// Values are applied verbatim; template expansion is not supported.
    #[serde(default)]
    #[configurable(metadata(
        docs::additional_props_description = "An HTTP request header and its static value."
    ))]
    #[configurable(metadata(docs::examples = "remote_write_headers_examples()"))]
    pub headers: BTreeMap<String, String>,
}

fn remote_write_headers_examples() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("Accept".to_string(), "text/plain".to_string()),
        ("X-My-Custom-Header".to_string(), "A-Value".to_string()),
    ])
}

fn validate_headers(
    headers: &BTreeMap<String, String>,
    configures_auth: bool,
) -> crate::Result<BTreeMap<OrderedHeaderName, HeaderValue>> {
    let headers = crate::sinks::util::http::validate_headers(headers)?;

    for name in headers.keys() {
        if configures_auth && name.inner() == AUTHORIZATION {
            return Err("Authorization header can not be used with defined auth options".into());
        }
    }

    Ok(headers)
}

/// Values derived while validating [`RemoteWriteConfig`], consumed by its `build`.
///
/// The fields are private, so the only way to obtain the parsed endpoint, validated headers,
/// confined tenant template, and batch settings the sink uses is [`ValidateSink::validate`].
pub struct ValidatedPrometheusRemoteWrite {
    endpoint: Uri,
    headers: BTreeMap<OrderedHeaderName, HeaderValue>,
    tenant_id: Option<ConfinedTemplate>,
    batch_settings: BatcherSettings,
    #[cfg(feature = "aws-core")]
    aws_region: Option<Region>,
}

impl fmt::Debug for ValidatedPrometheusRemoteWrite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = f.debug_struct("ValidatedPrometheusRemoteWrite");
        debug.field("endpoint", &self.endpoint);
        debug.field("headers", &self.headers);
        debug.field("tenant_id", &self.tenant_id.as_ref().map(|_| "<confined>"));
        debug.field("batch_settings", &self.batch_settings);
        #[cfg(feature = "aws-core")]
        debug.field("aws_region", &self.aws_region);
        debug.finish()
    }
}

impl ValidateSink for RemoteWriteConfig {
    type Validated = ValidatedPrometheusRemoteWrite;

    fn validate(&self) -> std::result::Result<Self::Validated, Vec<String>> {
        let mut errors = Vec::new();

        let endpoint = self
            .endpoint
            .parse::<Uri>()
            .inspect_err(|e| errors.push(format!("endpoint: invalid URI: {e}")))
            .ok();

        if let Some(uri) = &endpoint {
            if let Some(scheme) = uri.scheme() {
                if *scheme != http::uri::Scheme::HTTP && *scheme != http::uri::Scheme::HTTPS {
                    errors.push("endpoint: scheme must be http or https".to_string());
                }
            } else {
                errors.push("endpoint: must include a scheme (http:// or https://)".to_string());
            }
            if uri.host().is_none() {
                errors.push("endpoint: must include a host".to_string());
            }
        }

        let headers = validate_headers(&self.request.headers, self.auth.is_some())
            .inspect_err(|e| errors.push(format!("request.headers: {e}")))
            .ok();

        let tenant_id = self
            .tenant_id
            .clone()
            .map(|template| template.confine(&self.confinement, Self::NAME, "tenant_id"))
            .transpose()
            .inspect_err(|e| errors.push(e.to_string()))
            .ok();

        let batch_settings = self
            .batch
            .batch_settings
            .validate()
            .and_then(|batch_settings| batch_settings.into_batcher_settings())
            .inspect_err(|e| errors.push(format!("batch: {e}")))
            .ok();

        #[cfg(feature = "aws-core")]
        let aws_region = match &self.auth {
            Some(PrometheusRemoteWriteAuth::Aws(_)) => match &self.aws {
                None => {
                    errors.push(
                        "aws configuration is required when using AWS authentication".to_string(),
                    );
                    None
                }
                Some(aws_config) => match aws_config.region() {
                    Some(region) => Some(region),
                    None => {
                        errors.push(
                            "aws.region is required when using AWS authentication".to_string(),
                        );
                        None
                    }
                },
            },
            _ => None,
        };

        match (
            errors.is_empty(),
            endpoint,
            headers,
            tenant_id,
            batch_settings,
        ) {
            (true, Some(endpoint), Some(headers), Some(tenant_id), Some(batch_settings)) => {
                Ok(ValidatedPrometheusRemoteWrite {
                    endpoint,
                    headers,
                    tenant_id,
                    batch_settings,
                    #[cfg(feature = "aws-core")]
                    aws_region,
                })
            }
            _ => Err(errors),
        }
    }
}

#[async_trait::async_trait]
#[typetag::serde(name = "prometheus_remote_write")]
impl SinkConfig for RemoteWriteConfig {
    fn acknowledgements(&self) -> &AcknowledgementsConfig {
        &self.acknowledgements
    }

    fn validate_structure(&self) -> std::result::Result<(), Vec<String>> {
        self.validate().map(|_| ())
    }

    async fn build(&self, cx: SinkContext) -> crate::Result<(VectorSink, Healthcheck)> {
        let validated = self.validate().map_err(|errors| errors.join("; "))?;

        #[cfg(feature = "aws-core")]
        let aws_region = validated.aws_region;
        let endpoint = validated.endpoint;
        let tenant_id = validated.tenant_id;
        let batch_settings = validated.batch_settings;
        let tls_settings = TlsSettings::from_options(self.tls.as_ref())?;
        let request_settings = self.request.tower.into_settings();
        let validated_headers = Arc::new(validated.headers);
        let buckets = self.buckets.clone();
        let quantiles = self.quantiles.clone();
        let default_namespace = self.default_namespace.clone();

        let client = HttpClient::new(tls_settings, cx.proxy())?;

        let auth = match &self.auth {
            Some(PrometheusRemoteWriteAuth::Basic { user, password }) => {
                Some(Auth::Basic(crate::http::Auth::Basic {
                    user: user.clone(),
                    password: password.clone().into(),
                }))
            }
            Some(PrometheusRemoteWriteAuth::Bearer { token }) => {
                Some(Auth::Basic(crate::http::Auth::Bearer {
                    token: token.clone(),
                }))
            }
            #[cfg(feature = "aws-core")]
            Some(PrometheusRemoteWriteAuth::Aws(aws_auth)) => {
                let region = aws_region.ok_or(Errors::AwsRegionRequired)?;
                Some(Auth::Aws {
                    credentials_provider: aws_auth
                        .credentials_provider(region.clone(), cx.proxy(), self.tls.as_ref())
                        .await?,
                    region,
                })
            }
            None => None,
        };

        let healthcheck_endpoint = match cx.healthcheck.uri {
            Some(uri) => uri.uri,
            None => endpoint.clone(),
        };

        let healthcheck = healthcheck(
            client.clone(),
            healthcheck_endpoint,
            self.compression,
            auth.clone(),
            Arc::clone(&validated_headers),
        )
        .boxed();

        let service = RemoteWriteService {
            endpoint,
            client,
            auth,
            compression: self.compression,
            headers: validated_headers,
        };
        let service = ServiceBuilder::new()
            .settings(
                request_settings,
                http_response_retry_logic(self.retry_strategy.clone()),
            )
            .service(service);

        let sink = RemoteWriteSink {
            tenant_id,
            compression: self.compression,
            aggregate: self.batch.aggregate,
            batch_settings,
            buckets,
            quantiles,
            default_namespace,
            expire_metrics_secs: self.expire_metrics_secs,
            service,
        };
        Ok((VectorSink::from_event_streamsink(sink), healthcheck))
    }

    fn confinement_config(&self) -> Option<&crate::template::ConfinementConfig> {
        Some(&self.confinement)
    }

    fn input(&self) -> Input {
        Input::metric()
    }
}

async fn healthcheck(
    client: HttpClient,
    endpoint: Uri,
    compression: Compression,
    auth: Option<Auth>,
    headers: Arc<BTreeMap<OrderedHeaderName, HeaderValue>>,
) -> crate::Result<()> {
    let body = bytes::Bytes::new();
    let request = build_request(
        http::Method::GET,
        &endpoint,
        compression,
        body,
        None,
        auth,
        headers,
    )
    .await?;
    let response = client.send(request).await?;

    match response.status() {
        http::StatusCode::OK => Ok(()),
        other => Err(HealthcheckError::UnexpectedStatus { status: other }.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::template::{ConfinementConfig, Template};

    #[test]
    fn generate_config() {
        crate::test_util::test_generate_config::<RemoteWriteConfig>();
    }

    #[test]
    fn confinement_rejects_unconfined_tenant_id() {
        let template = Template::try_from("{{ tenant }}").unwrap();
        let config = ConfinementConfig::default();
        let result = template.confine(&config, "prometheus_remote_write", "tenant_id");
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
        let result = template.confine(&config, "prometheus_remote_write", "tenant_id");
        assert!(result.is_ok(), "opt-out must allow bare tenant_id template");
    }

    #[test]
    fn confinement_prefixed_tenant_id_locks_org_prefix() {
        use crate::event::{Event, LogEvent};
        use vrl::event_path;
        let template = Template::try_from("team-{{ org }}").unwrap();
        let config = ConfinementConfig::default();
        let confined = template
            .confine(&config, "prometheus_remote_write", "tenant_id")
            .unwrap();
        let mut event = LogEvent::default();
        event.insert(event_path!("org"), "other-tenant-entirely");
        let rendered = confined.render_string(&Event::Log(event)).unwrap();
        assert!(
            rendered.starts_with("team-"),
            "operator-controlled prefix must be preserved in rendered tenant_id"
        );
    }

    #[test]
    fn validate_yields_remote_write_values() {
        use crate::event::{Event, LogEvent};
        use vrl::event_path;

        let mut headers = BTreeMap::new();
        headers.insert("X-Custom-Header".to_string(), "custom-value".to_string());

        let config = RemoteWriteConfig {
            endpoint: "https://localhost:8087/api/v1/write".to_string(),
            request: RemoteWriteRequestConfig {
                headers,
                ..Default::default()
            },
            tenant_id: Some(Template::try_from("tenant-{{ org }}").unwrap()),
            ..Default::default()
        };

        let validated = config.validate().unwrap();
        assert_eq!(
            validated.endpoint.to_string(),
            "https://localhost:8087/api/v1/write"
        );
        assert_eq!(validated.headers.len(), 1);
        let (name, value) = validated.headers.iter().next().unwrap();
        assert_eq!(name.inner().as_str(), "x-custom-header");
        assert_eq!(value, &HeaderValue::from_static("custom-value"));
        assert_eq!(validated.batch_settings.item_limit, 1_000);

        let mut event = LogEvent::default();
        event.insert(event_path!("org"), "blue");
        let rendered = validated
            .tenant_id
            .unwrap()
            .render_string(&Event::Log(event))
            .unwrap();
        assert_eq!(rendered, "tenant-blue");
    }

    #[test]
    fn validate_structure_rejects_invalid_endpoint() {
        use crate::config::SinkConfig;

        let config = RemoteWriteConfig {
            endpoint: "not a valid uri".to_string(),
            ..Default::default()
        };

        let errors = config.validate_structure().unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| e.contains("endpoint") && e.contains("invalid URI")),
            "unexpected errors: {:?}",
            errors
        );
    }

    #[test]
    fn validate_structure_rejects_authorization_header_with_auth() {
        use crate::config::SinkConfig;
        use crate::sinks::prometheus::PrometheusRemoteWriteAuth;

        let mut headers = BTreeMap::new();
        headers.insert("Authorization".to_string(), "Bearer token".to_string());

        let config = RemoteWriteConfig {
            endpoint: "https://localhost:8087/api/v1/write".to_string(),
            request: RemoteWriteRequestConfig {
                headers,
                ..Default::default()
            },
            auth: Some(PrometheusRemoteWriteAuth::Bearer {
                token: "test".to_string().into(),
            }),
            ..Default::default()
        };

        let errors = config.validate_structure().unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| e.contains("Authorization") && e.contains("auth options")),
            "unexpected errors: {:?}",
            errors
        );
    }

    #[test]
    fn validate_structure_rejects_malformed_headers() {
        use crate::config::SinkConfig;

        let mut headers = BTreeMap::new();
        headers.insert("Invalid-Header\n".to_string(), "value".to_string());

        let config = RemoteWriteConfig {
            endpoint: "https://localhost:8087/api/v1/write".to_string(),
            request: RemoteWriteRequestConfig {
                headers,
                ..Default::default()
            },
            ..Default::default()
        };

        let errors = config.validate_structure().unwrap_err();
        assert!(
            errors.iter().any(|e| e.contains("headers")),
            "unexpected errors: {:?}",
            errors
        );
    }

    #[test]
    fn validate_structure_rejects_non_http_scheme() {
        use crate::config::SinkConfig;

        let config = RemoteWriteConfig {
            endpoint: "ftp://localhost:8087/api/v1/write".to_string(),
            ..Default::default()
        };

        let errors = config.validate_structure().unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| e.contains("scheme") && e.contains("http")),
            "unexpected errors: {:?}",
            errors
        );
    }

    #[cfg(feature = "aws-core")]
    #[test]
    fn validate_structure_rejects_aws_auth_without_aws_config() {
        use crate::config::SinkConfig;
        use crate::sinks::prometheus::PrometheusRemoteWriteAuth;

        let config = RemoteWriteConfig {
            endpoint: "https://localhost:8087/api/v1/write".to_string(),
            auth: Some(PrometheusRemoteWriteAuth::Aws(
                crate::aws::AwsAuthentication::default(),
            )),
            ..Default::default()
        };

        let errors = config.validate_structure().unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| e.contains("aws configuration is required")),
            "unexpected errors: {:?}",
            errors
        );
    }

    #[cfg(feature = "aws-core")]
    #[test]
    fn validate_structure_rejects_aws_auth_without_region() {
        use crate::config::SinkConfig;
        use crate::sinks::prometheus::PrometheusRemoteWriteAuth;

        let config = RemoteWriteConfig {
            endpoint: "https://localhost:8087/api/v1/write".to_string(),
            auth: Some(PrometheusRemoteWriteAuth::Aws(
                crate::aws::AwsAuthentication::default(),
            )),
            aws: Some(crate::aws::RegionOrEndpoint {
                region: None,
                endpoint: Some("http://localhost:4566".to_string()),
            }),
            ..Default::default()
        };

        let errors = config.validate_structure().unwrap_err();
        assert!(
            errors.iter().any(|e| e.contains("aws.region is required")),
            "unexpected errors: {:?}",
            errors
        );
    }
}
