use std::sync::Arc;

use futures_util::FutureExt;
use tower::ServiceBuilder;
use vector_lib::{
    configurable::configurable_component, lookup::lookup_v2::OptionalValuePath,
    sensitive_string::SensitiveString, sink::VectorSink, stream::BatcherSettings,
};

use super::{request_builder::HecMetricsRequestBuilder, sink::HecMetricsSink};

use crate::{
    config::{
        AcknowledgementsConfig, GenerateConfig, Input, SinkConfig, SinkContext, ValidateSink,
    },
    http::HttpClient,
    sinks::{
        Healthcheck,
        splunk_hec::common::{
            EndpointTarget, SplunkHecDefaultBatchSettings,
            acknowledgements::HecClientAcknowledgementsConfig,
            build_healthcheck, build_http_batch_service, config_host_key, create_client,
            service::{HecService, HttpRequestBuilder},
        },
        util::{
            BatchConfig, Compression, ServiceBuilderExt, TowerRequestConfig, http::HttpRetryLogic,
        },
    },
    template::{ConfinedTemplate, Template},
    tls::TlsConfig,
};

/// Configuration of the `splunk_hec_metrics` sink.
#[configurable_component(sink(
    "splunk_hec_metrics",
    "Deliver metric data to Splunk's HTTP Event Collector."
))]
#[derive(Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct HecMetricsSinkConfig {
    /// Sets the default namespace for any metrics sent.
    ///
    /// This namespace is only used if a metric has no existing namespace. When a namespace is
    /// present, it is used as a prefix to the metric name, and separated with a period (`.`).
    #[configurable(metadata(docs::examples = "service"))]
    pub default_namespace: Option<String>,

    /// Default Splunk HEC token.
    ///
    /// If an event has a token set in its metadata, it prevails over the one set here.
    #[serde(alias = "token")]
    #[configurable(metadata(
        docs::examples = "${SPLUNK_HEC_TOKEN}",
        docs::examples = "A94A8FE5CCB19BA61C4C08"
    ))]
    pub default_token: SensitiveString,

    /// The base URL of the Splunk instance.
    ///
    /// The scheme (`http` or `https`) must be specified. No path should be included since the paths defined
    /// by the [`Splunk`][splunk] API are used.
    ///
    /// [splunk]: https://docs.splunk.com/Documentation/Splunk/8.0.0/Data/HECRESTendpoints
    #[configurable(metadata(
        docs::examples = "https://http-inputs-hec.splunkcloud.com",
        docs::examples = "https://hec.splunk.com:8088",
        docs::examples = "http://example.com"
    ))]
    #[configurable(validation(format = "uri"))]
    pub endpoint: String,

    /// Overrides the name of the log field used to retrieve the hostname to send to Splunk HEC.
    ///
    /// By default, the [global `log_schema.host_key` option][global_host_key] is used.
    ///
    /// [global_host_key]: https://vector.dev/docs/reference/configuration/global-options/#log_schema.host_key
    #[configurable(metadata(docs::advanced))]
    #[serde(default = "config_host_key")]
    pub host_key: OptionalValuePath,

    /// The name of the index where to send the events to.
    ///
    /// If not specified, the default index defined within Splunk is used.
    #[configurable(metadata(docs::examples = "{{ host }}", docs::examples = "custom_index"))]
    pub index: Option<Template>,

    /// The sourcetype of events sent to this sink.
    ///
    /// If unset, Splunk defaults to `httpevent`.
    #[configurable(metadata(docs::advanced))]
    #[configurable(metadata(docs::examples = "{{ sourcetype }}", docs::examples = "_json",))]
    pub sourcetype: Option<Template>,

    /// The source of events sent to this sink.
    ///
    /// This is typically the filename the logs originated from.
    ///
    /// If unset, the Splunk collector sets it.
    #[configurable(metadata(docs::advanced))]
    #[configurable(metadata(
        docs::examples = "{{ file }}",
        docs::examples = "/var/log/syslog",
        docs::examples = "UDP:514"
    ))]
    pub source: Option<Template>,

    #[configurable(derived)]
    #[serde(default)]
    pub compression: Compression,

    #[configurable(derived)]
    #[serde(default)]
    pub batch: BatchConfig<SplunkHecDefaultBatchSettings>,

    #[configurable(derived)]
    #[serde(default)]
    pub request: TowerRequestConfig,

    #[configurable(derived)]
    pub tls: Option<TlsConfig>,

    #[configurable(derived)]
    #[serde(default)]
    pub acknowledgements: HecClientAcknowledgementsConfig,

    #[configurable(derived)]
    #[serde(flatten)]
    pub confinement: crate::template::ConfinementConfig,
}

impl GenerateConfig for HecMetricsSinkConfig {
    fn generate_config() -> serde_json::Value {
        serde_json::to_value(Self {
            default_namespace: None,
            default_token: "${VECTOR_SPLUNK_HEC_TOKEN}".to_owned().into(),
            endpoint: "http://localhost:8088".to_owned(),
            host_key: config_host_key(),
            index: None,
            sourcetype: None,
            source: None,
            compression: Compression::default(),
            batch: BatchConfig::default(),
            request: TowerRequestConfig::default(),
            tls: None,
            acknowledgements: Default::default(),
            confinement: Default::default(),
        })
        .unwrap()
    }
}

/// Values derived while validating [`HecMetricsSinkConfig`], consumed by its `build`.
///
/// The fields are private, so the only way to obtain the confined templates and batch settings the
/// sink renders with is [`ValidateSink::validate`].
#[derive(Debug)]
pub struct ValidatedHecMetricsSink {
    sourcetype: Option<ConfinedTemplate>,
    source: Option<ConfinedTemplate>,
    index: Option<ConfinedTemplate>,
    batch_settings: BatcherSettings,
}

impl ValidateSink for HecMetricsSinkConfig {
    type Validated = ValidatedHecMetricsSink;

    fn validate(&self) -> std::result::Result<Self::Validated, Vec<String>> {
        let mut errors = Vec::new();

        let sourcetype = self
            .sourcetype
            .clone()
            .map(|t| t.confine(&self.confinement, Self::NAME, "sourcetype"))
            .transpose()
            .inspect_err(|e| errors.push(e.to_string()))
            .ok();

        let source = self
            .source
            .clone()
            .map(|t| t.confine(&self.confinement, Self::NAME, "source"))
            .transpose()
            .inspect_err(|e| errors.push(e.to_string()))
            .ok();

        let index = self
            .index
            .clone()
            .map(|t| t.confine(&self.confinement, Self::NAME, "index"))
            .transpose()
            .inspect_err(|e| errors.push(e.to_string()))
            .ok();

        let batch_settings = self
            .batch
            .into_batcher_settings()
            .inspect_err(|e| errors.push(format!("batch: {e}")))
            .ok();

        match (errors.is_empty(), sourcetype, source, index, batch_settings) {
            (true, Some(sourcetype), Some(source), Some(index), Some(batch_settings)) => {
                Ok(ValidatedHecMetricsSink {
                    sourcetype,
                    source,
                    index,
                    batch_settings,
                })
            }
            _ => Err(errors),
        }
    }
}

#[async_trait::async_trait]
#[typetag::serde(name = "splunk_hec_metrics")]
impl SinkConfig for HecMetricsSinkConfig {
    async fn build(&self, cx: SinkContext) -> crate::Result<(VectorSink, Healthcheck)> {
        let validated = self.validate().map_err(|errors| errors.join("; "))?;

        let templated_field_keys =
            compute_templated_field_keys(&self.index, &self.source, &self.sourcetype);

        let client = create_client(self.tls.as_ref(), cx.proxy())?;
        let healthcheck = build_healthcheck(
            self.endpoint.clone(),
            self.default_token.inner().to_owned(),
            client.clone(),
        )
        .boxed();
        let sink = self.build_processor(client, cx, validated, templated_field_keys)?;
        Ok((sink, healthcheck))
    }

    fn confinement_config(&self) -> Option<&crate::template::ConfinementConfig> {
        Some(&self.confinement)
    }

    fn input(&self) -> Input {
        Input::metric()
    }

    fn acknowledgements(&self) -> &AcknowledgementsConfig {
        &self.acknowledgements.inner
    }

    fn validate_structure(&self) -> std::result::Result<(), Vec<String>> {
        self.validate().map(|_| ())
    }
}

pub(super) fn compute_templated_field_keys(
    index: &Option<Template>,
    source: &Option<Template>,
    sourcetype: &Option<Template>,
) -> Box<[String]> {
    [index, source, sourcetype]
        .iter()
        .filter_map(|t| t.as_ref())
        .filter_map(|t| t.get_fields())
        .flatten()
        .map(|f| f.replace("tags.", ""))
        .collect()
}

impl HecMetricsSinkConfig {
    pub fn build_processor(
        &self,
        client: HttpClient,
        _: SinkContext,
        validated: ValidatedHecMetricsSink,
        // Feeds the encoder rather than per-event metadata.
        templated_field_keys: Box<[String]>,
    ) -> crate::Result<VectorSink> {
        let ValidatedHecMetricsSink {
            sourcetype,
            source,
            index,
            batch_settings,
        } = validated;

        let ack_client = if self.acknowledgements.indexer_acknowledgements_enabled {
            Some(client.clone())
        } else {
            None
        };

        let request_builder = HecMetricsRequestBuilder::new(self.compression, templated_field_keys);

        let request_settings = self.request.into_settings();
        let http_request_builder = Arc::new(HttpRequestBuilder::new(
            self.endpoint.clone(),
            EndpointTarget::default(),
            self.default_token.inner().to_owned(),
            self.compression,
        ));
        let http_service = ServiceBuilder::new()
            .settings(request_settings, HttpRetryLogic::default())
            .service(build_http_batch_service(
                client,
                Arc::clone(&http_request_builder),
                EndpointTarget::Event,
                false,
            ));

        let service = HecService::new(
            http_service,
            ack_client,
            http_request_builder,
            self.acknowledgements.clone(),
        );

        let sink = HecMetricsSink {
            service,
            batch_settings,
            request_builder,
            sourcetype,
            source,
            index,
            host_key: self.host_key.path.clone(),
            default_namespace: self.default_namespace.clone(),
        };

        Ok(VectorSink::from_event_streamsink(sink))
    }
}

#[cfg(test)]
mod tests {
    use vector_lib::{
        event::{Metric, MetricKind, MetricValue},
        metric_tags,
    };

    use super::*;
    use crate::template::ConfinementConfig;

    #[test]
    fn validate_yields_confined_templates_and_batch_settings() {
        let config = HecMetricsSinkConfig {
            default_namespace: None,
            default_token: "test-token".to_string().into(),
            endpoint: "http://localhost:8088".to_string(),
            host_key: config_host_key(),
            index: Some(Template::try_from("index-{{ tags.env }}").unwrap()),
            sourcetype: Some(Template::try_from("type-{{ tags.env }}").unwrap()),
            source: Some(Template::try_from("source-{{ tags.env }}").unwrap()),
            compression: Compression::default(),
            batch: BatchConfig::default(),
            request: TowerRequestConfig::default(),
            tls: None,
            acknowledgements: Default::default(),
            confinement: ConfinementConfig::default(),
        };

        let validated = config.validate().expect("config is valid");

        let metric = Metric::new(
            "cpu",
            MetricKind::Absolute,
            MetricValue::Gauge { value: 1.0 },
        )
        .with_tags(Some(metric_tags! {
            "env".to_string() => "prod".to_string(),
        }));

        assert_eq!(
            validated
                .index
                .as_ref()
                .unwrap()
                .render_string(&metric)
                .unwrap(),
            "index-prod"
        );
        assert_eq!(
            validated
                .sourcetype
                .as_ref()
                .unwrap()
                .render_string(&metric)
                .unwrap(),
            "type-prod"
        );
        assert_eq!(
            validated
                .source
                .as_ref()
                .unwrap()
                .render_string(&metric)
                .unwrap(),
            "source-prod"
        );
        assert!(validated.batch_settings.item_limit > 0);
    }
}
