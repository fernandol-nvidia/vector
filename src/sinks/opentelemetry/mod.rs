use indoc::indoc;
use vector_config::component::GenerateConfig;
use vector_lib::{
    codecs::{
        JsonSerializerConfig,
        encoding::{FramingConfig, SerializerConfig},
    },
    configurable::configurable_component,
};

use crate::{
    codecs::{EncodingConfigWithFraming, Transformer},
    config::{AcknowledgementsConfig, Input, SinkConfig, SinkContext, ValidateSink},
    sinks::{
        Healthcheck, VectorSink,
        http::config::{HttpMethod, HttpSinkConfig, ValidatedHttpSink},
    },
};

/// Configuration for the `OpenTelemetry` sink.
#[configurable_component(sink("opentelemetry", "Deliver OTLP data over HTTP."))]
#[derive(Clone, Debug, Default)]
pub struct OpenTelemetryConfig {
    /// Protocol configuration
    #[configurable(derived)]
    protocol: Protocol,
}

/// The protocol used to send data to OpenTelemetry.
/// Currently only HTTP is supported, but we plan to support gRPC.
/// The proto definitions are defined [here](https://github.com/vectordotdev/vector/blob/master/lib/opentelemetry-proto/src/proto/opentelemetry-proto/opentelemetry/proto/README.md).
#[configurable_component]
#[derive(Clone, Debug)]
#[serde(rename_all = "snake_case", tag = "type")]
#[configurable(metadata(docs::enum_tag_description = "The communication protocol."))]
pub enum Protocol {
    /// Send data over HTTP.
    Http(HttpSinkConfig),
}

impl Default for Protocol {
    fn default() -> Self {
        Protocol::Http(HttpSinkConfig {
            encoding: EncodingConfigWithFraming::new(
                Some(FramingConfig::NewlineDelimited),
                SerializerConfig::Json(JsonSerializerConfig::default()),
                Transformer::default(),
            ),
            uri: Default::default(),
            method: HttpMethod::Post,
            auth: Default::default(),
            compression: Default::default(),
            payload_prefix: Default::default(),
            payload_suffix: Default::default(),
            batch: Default::default(),
            request: Default::default(),
            tls: Default::default(),
            acknowledgements: Default::default(),
            retry_strategy: Default::default(),
            confinement: Default::default(),
        })
    }
}

impl GenerateConfig for OpenTelemetryConfig {
    fn generate_config() -> serde_json::Value {
        toml::from_str(indoc! {r#"
            [protocol]
            type = "http"
            uri = "http://localhost:5318/v1/logs"
            encoding.codec = "json"
        "#})
        .unwrap()
    }
}

/// Values derived while validating [`OpenTelemetryConfig`], consumed by its `build`.
///
/// The field is private, so the only way to obtain the validated HTTP values OpenTelemetry
/// delegates to is [`ValidateSink::validate`].
#[derive(Debug)]
pub struct ValidatedOpenTelemetry {
    http: ValidatedHttpSink,
}

impl ValidateSink for OpenTelemetryConfig {
    type Validated = ValidatedOpenTelemetry;

    fn validate(&self) -> std::result::Result<Self::Validated, Vec<String>> {
        match &self.protocol {
            Protocol::Http(config) => config
                .validate_with_component_type(Self::NAME)
                .map(|http| ValidatedOpenTelemetry { http }),
        }
    }
}

#[async_trait::async_trait]
#[typetag::serde(name = "opentelemetry")]
impl SinkConfig for OpenTelemetryConfig {
    async fn build(&self, cx: SinkContext) -> crate::Result<(VectorSink, Healthcheck)> {
        let ValidatedOpenTelemetry { http } =
            self.validate().map_err(|errors| errors.join("; "))?;

        match &self.protocol {
            Protocol::Http(config) => {
                warn_on_invalid_otlp_batching(config);
                // Delegate to the HTTP sink with values validated using `opentelemetry` as the
                // component type so confinement diagnostics carry the outer sink type.
                config.build_with_component_type(cx, Self::NAME, http).await
            }
        }
    }

    fn confinement_config(&self) -> Option<&crate::template::ConfinementConfig> {
        match &self.protocol {
            Protocol::Http(config) => Some(&config.confinement),
        }
    }

    fn input(&self) -> Input {
        match &self.protocol {
            Protocol::Http(config) => config.input(),
        }
    }

    fn acknowledgements(&self) -> &AcknowledgementsConfig {
        match self.protocol {
            Protocol::Http(ref config) => config.acknowledgements(),
        }
    }

    fn validate_structure(&self) -> std::result::Result<(), Vec<String>> {
        self.validate().map(|_| ())
    }
}

fn warn_on_invalid_otlp_batching(config: &HttpSinkConfig) {
    let (_, serializer) = config.encoding.config();
    let is_json = matches!(serializer, SerializerConfig::Json(_));
    let batches_more_than_one = !matches!(config.batch.max_events, Some(1));
    if is_json && batches_more_than_one {
        tracing::warn!(
            message = "`opentelemetry` sink is configured with `encoding.codec = json` and \
                       `batch.max_events` greater than 1. This produces invalid OTLP request \
                       bodies that receivers reject with HTTP 400. Use `encoding.codec = otlp` \
                       (recommended) or set `batch.max_events = 1`. See \
                       https://github.com/vectordotdev/vector/issues/22054.",
        );
    }
}

#[cfg(test)]
mod test {
    use vector_lib::codecs::encoding::{FramingConfig, JsonSerializerConfig, SerializerConfig};

    use super::*;
    use crate::{
        codecs::{EncodingConfigWithFraming, Transformer},
        sinks::{
            http::config::HttpSinkConfig,
            util::{
                BatchConfig, Compression,
                http::{RequestConfig, RetryStrategy},
            },
        },
        template::Template,
    };

    #[test]
    fn generate_config() {
        crate::test_util::test_generate_config::<OpenTelemetryConfig>();
    }

    #[test]
    fn confinement_rejects_unconfined_uri() {
        let config = OpenTelemetryConfig {
            protocol: Protocol::Http(HttpSinkConfig {
                uri: Template::try_from("{{ target }}").unwrap(),
                compression: Compression::default(),
                auth: None,
                method: Default::default(),
                tls: None,
                request: RequestConfig::default(),
                acknowledgements: Default::default(),
                batch: BatchConfig::default(),
                encoding: EncodingConfigWithFraming::new(
                    Some(FramingConfig::NewlineDelimited),
                    SerializerConfig::Json(JsonSerializerConfig::default()),
                    Transformer::default(),
                ),
                payload_prefix: "".into(),
                payload_suffix: "".into(),
                retry_strategy: RetryStrategy::default(),
                confinement: crate::template::ConfinementConfig::default(),
            }),
        };

        let errors = config.validate_structure().unwrap_err();
        assert_eq!(errors.len(), 1);
        assert!(
            errors[0].contains("no literal string prefix"),
            "unexpected error: {:?}",
            errors[0]
        );
    }

    #[test]
    fn confinement_allows_prefixed_uri() {
        let config = OpenTelemetryConfig {
            protocol: Protocol::Http(HttpSinkConfig {
                uri: Template::try_from("http://localhost/{{ path }}").unwrap(),
                compression: Compression::default(),
                auth: None,
                method: Default::default(),
                tls: None,
                request: RequestConfig::default(),
                acknowledgements: Default::default(),
                batch: BatchConfig::default(),
                encoding: EncodingConfigWithFraming::new(
                    Some(FramingConfig::NewlineDelimited),
                    SerializerConfig::Json(JsonSerializerConfig::default()),
                    Transformer::default(),
                ),
                payload_prefix: "".into(),
                payload_suffix: "".into(),
                retry_strategy: RetryStrategy::default(),
                confinement: crate::template::ConfinementConfig::default(),
            }),
        };

        config.validate_structure().unwrap();
    }
}
