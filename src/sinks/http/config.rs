//! Configuration for the `http` sink.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
};

#[cfg(feature = "aws-core")]
use aws_config::meta::region::ProvideRegion;
#[cfg(feature = "aws-core")]
use aws_types::region::Region;
use http::{HeaderName, HeaderValue, Method, Request, StatusCode, header::AUTHORIZATION};
use hyper::Body;
use vector_lib::codecs::{
    CharacterDelimitedEncoder,
    encoding::{Framer, Serializer},
};
#[cfg(feature = "aws-core")]
use vector_lib::config::proxy::ProxyConfig;

use super::{
    encoder::HttpEncoder, request_builder::HttpRequestBuilder, service::HttpSinkRequestBuilder,
    sink::HttpSink,
};
#[cfg(feature = "aws-core")]
use crate::aws::AwsAuthentication;
#[cfg(feature = "aws-core")]
use crate::sinks::util::http::SigV4Config;
use crate::{
    codecs::{EncodingConfigWithFraming, SinkType},
    http::{Auth, HttpClient, MaybeAuth},
    sinks::{
        prelude::*,
        util::{
            RealtimeSizeBasedDefaultBatchSettings, UriSerde,
            http::{
                HttpService, OrderedHeaderName, RequestConfig, RetryStrategy,
                http_response_retry_logic,
            },
        },
    },
    template::ConfinementConfig,
};

const CONTENT_TYPE_TEXT: &str = "text/plain";
const CONTENT_TYPE_NDJSON: &str = "application/x-ndjson";
const CONTENT_TYPE_JSON: &str = "application/json";

/// Configuration for the `http` sink.
#[configurable_component(sink("http", "Deliver observability event data to an HTTP server."))]
#[derive(Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct HttpSinkConfig {
    /// The full URI to make HTTP requests to.
    ///
    /// This should include the protocol and host, but can also include the port, path, and any other valid part of a URI.
    #[configurable(metadata(docs::examples = "https://10.22.212.22:9000/endpoint"))]
    pub uri: Template,

    /// The HTTP method to use when making the request.
    #[serde(default)]
    pub method: HttpMethod,

    #[configurable(derived)]
    pub auth: Option<Auth>,

    #[configurable(derived)]
    #[serde(default)]
    pub compression: Compression,

    #[serde(flatten)]
    pub encoding: EncodingConfigWithFraming,

    /// A string to prefix the payload with.
    ///
    /// This option is ignored if the encoding is not character delimited JSON.
    ///
    /// If specified, the `payload_suffix` must also be specified and together they must produce a valid JSON object.
    #[configurable(metadata(docs::examples = "{\"data\":"))]
    #[serde(default)]
    pub payload_prefix: String,

    /// A string to suffix the payload with.
    ///
    /// This option is ignored if the encoding is not character delimited JSON.
    ///
    /// If specified, the `payload_prefix` must also be specified and together they must produce a valid JSON object.
    #[configurable(metadata(docs::examples = "}"))]
    #[serde(default)]
    pub payload_suffix: String,

    #[configurable(derived)]
    #[serde(default)]
    pub batch: BatchConfig<RealtimeSizeBasedDefaultBatchSettings>,

    #[configurable(derived)]
    #[serde(default)]
    pub request: RequestConfig,

    #[configurable(derived)]
    pub tls: Option<TlsConfig>,

    #[configurable(derived)]
    #[serde(
        default,
        deserialize_with = "crate::serde::bool_or_struct",
        skip_serializing_if = "crate::serde::is_default"
    )]
    pub acknowledgements: AcknowledgementsConfig,

    #[configurable(derived)]
    #[serde(default)]
    pub retry_strategy: RetryStrategy,

    #[serde(flatten)]
    pub confinement: ConfinementConfig,
}

/// HTTP method.
///
/// A subset of the HTTP methods described in [RFC 9110, section 9.1][rfc9110] are supported.
///
/// [rfc9110]: https://datatracker.ietf.org/doc/html/rfc9110#section-9.1
#[configurable_component]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum HttpMethod {
    /// GET.
    Get,

    /// HEAD.
    Head,

    /// POST.
    #[default]
    Post,

    /// PUT.
    Put,

    /// DELETE.
    Delete,

    /// OPTIONS.
    Options,

    /// TRACE.
    Trace,

    /// PATCH.
    Patch,
}

impl From<HttpMethod> for Method {
    fn from(http_method: HttpMethod) -> Self {
        match http_method {
            HttpMethod::Head => Self::HEAD,
            HttpMethod::Get => Self::GET,
            HttpMethod::Post => Self::POST,
            HttpMethod::Put => Self::PUT,
            HttpMethod::Patch => Self::PATCH,
            HttpMethod::Delete => Self::DELETE,
            HttpMethod::Options => Self::OPTIONS,
            HttpMethod::Trace => Self::TRACE,
        }
    }
}

impl HttpSinkConfig {
    fn build_http_client(&self, cx: &SinkContext) -> crate::Result<HttpClient> {
        let tls = TlsSettings::from_options(self.tls.as_ref())?;
        Ok(HttpClient::new(tls, cx.proxy())?)
    }

    pub(super) fn build_encoder(&self) -> crate::Result<Encoder<Framer>> {
        let (framer, serializer) = self.encoding.build(SinkType::MessageBased)?;
        Ok(Encoder::<Framer>::new(framer, serializer))
    }
}

impl GenerateConfig for HttpSinkConfig {
    fn generate_config() -> serde_json::Value {
        toml::from_str(
            r#"uri = "https://10.22.212.22:9000/endpoint"
            encoding.codec = "json""#,
        )
        .unwrap()
    }
}

async fn healthcheck(uri: UriSerde, auth: Option<Auth>, client: HttpClient) -> crate::Result<()> {
    let auth = auth.choose_one(&uri.auth)?;
    let uri = uri.with_default_parts();
    let mut request = Request::head(&uri.uri).body(Body::empty()).unwrap();

    if let Some(auth) = auth {
        auth.apply(&mut request);
    }

    let response = client.send(request).await?;

    match response.status() {
        StatusCode::OK => Ok(()),
        status => Err(HealthcheckError::UnexpectedStatus { status }.into()),
    }
}

pub(super) fn validate_headers(
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

pub(super) fn validate_payload_wrapper(
    payload_prefix: &str,
    payload_suffix: &str,
    encoder: &Encoder<Framer>,
) -> crate::Result<(String, String)> {
    let payload = [payload_prefix, "{}", payload_suffix].join("");
    match (
        encoder.serializer(),
        encoder.framer(),
        serde_json::from_str::<serde_json::Value>(&payload),
    ) {
        (
            Serializer::Json(_),
            Framer::CharacterDelimited(CharacterDelimitedEncoder { delimiter: b',' }),
            Err(_),
        ) => Err("Payload prefix and suffix wrapper must produce a valid JSON object.".into()),
        _ => Ok((payload_prefix.to_owned(), payload_suffix.to_owned())),
    }
}

/// Values derived while validating [`HttpSinkConfig`], consumed by its `build`.
///
/// The fields are private, so the only way to obtain the confined templates and other derived
/// settings the sink uses is [`ValidateSink::validate`] or the component-aware validator used by
/// wrapper sinks.
#[derive(Debug)]
pub struct ValidatedHttpSink {
    batch_settings: BatcherSettings,
    encoder: Option<Encoder<Framer>>,
    payload_prefix: String,
    payload_suffix: String,
    static_headers: BTreeMap<OrderedHeaderName, HeaderValue>,
    template_headers: BTreeMap<String, ConfinedTemplate>,
    uri: ConfinedTemplate,
}

impl ValidateSink for HttpSinkConfig {
    type Validated = ValidatedHttpSink;

    fn validate(&self) -> std::result::Result<Self::Validated, Vec<String>> {
        self.validate_with_component_type(Self::NAME)
    }
}

impl HttpSinkConfig {
    pub(crate) fn validate_with_component_type(
        &self,
        component_name: &'static str,
    ) -> std::result::Result<ValidatedHttpSink, Vec<String>> {
        let mut errors = Vec::new();

        let batch_settings = self
            .batch
            .into_batcher_settings()
            .inspect_err(|e| errors.push(format!("batch: {e}")))
            .ok();

        let uri = self
            .uri
            .clone()
            .confine(&self.confinement, component_name, "uri")
            .inspect_err(|e| errors.push(e.to_string()))
            .ok();

        if !self.uri.is_dynamic() {
            match self.uri.get_ref().parse::<UriSerde>() {
                Ok(uri_serde) => {
                    let scheme = uri_serde.uri.scheme();
                    if scheme.is_none() {
                        errors.push("uri: must include a scheme (http:// or https://)".to_string());
                    }
                    if let Some(s) = scheme
                        && s != "http"
                        && s != "https"
                    {
                        errors.push(format!("uri: scheme must be http or https, got '{}'", s));
                    }
                    if uri_serde.uri.host().is_none() {
                        errors.push("uri: must include a host".to_string());
                    }
                    if let Err(e) = self.auth.choose_one(&uri_serde.auth) {
                        errors.push(format!("auth: {e}"));
                    }
                }
                Err(e) => {
                    errors.push(format!("uri: invalid URI: {e}"));
                }
            }
        } else if let Ok(uri_serde) = self.uri.literal_prefix().parse::<UriSerde>()
            && self.auth.choose_one(&uri_serde.auth).is_err()
        {
            errors.push(
                "uri: contains embedded credentials that conflict with `auth`. Remove credentials from the URI or remove `auth`.".to_string(),
            );
        }

        let request_headers = validate_headers(&self.request.headers, self.auth.is_some())
            .inspect_err(|e| errors.push(format!("request.headers: {e}")))
            .ok();

        let (static_headers, template_headers) = self.request.split_headers();

        let static_header_names = static_headers
            .keys()
            .filter_map(|name| {
                HeaderName::from_bytes(name.as_bytes())
                    .ok()
                    .map(OrderedHeaderName::from)
            })
            .collect::<BTreeSet<_>>();

        let static_headers = request_headers.map(|headers| {
            headers
                .into_iter()
                .filter(|(name, _)| static_header_names.contains(name))
                .collect::<BTreeMap<_, _>>()
        });

        let mut confined_template_headers = BTreeMap::new();
        let mut template_headers_valid = true;
        for (name, tpl) in template_headers.into_iter() {
            match tpl.confine(&self.confinement, component_name, "request.headers") {
                Ok(tpl) => {
                    if template_headers_valid {
                        confined_template_headers.insert(name, tpl);
                    }
                }
                Err(e) => {
                    errors.push(format!("headers.{}: {}", name, e));
                    template_headers_valid = false;
                }
            }
        }
        let template_headers = template_headers_valid.then_some(confined_template_headers);

        if let Err(e) = self.encoding.validate_structure() {
            errors.push(format!("encoding: {e}"));
        }

        let serializer = self.encoding.config().1;
        let needs_external_file = matches!(
            serializer,
            vector_lib::codecs::encoding::SerializerConfig::Protobuf(_)
        );

        let encoder = if needs_external_file {
            None
        } else {
            self.build_encoder()
                .inspect_err(|e| errors.push(format!("encoding: {e}")))
                .ok()
        };

        let payload_wrapper = match &encoder {
            Some(encoder) => {
                validate_payload_wrapper(&self.payload_prefix, &self.payload_suffix, encoder)
                    .inspect_err(|e| errors.push(format!("payload_prefix/payload_suffix: {e}")))
                    .ok()
            }
            None if needs_external_file => {
                Some((self.payload_prefix.clone(), self.payload_suffix.clone()))
            }
            None => None,
        };

        match (
            errors.is_empty(),
            batch_settings,
            uri,
            static_headers,
            template_headers,
            payload_wrapper,
        ) {
            (
                true,
                Some(batch_settings),
                Some(uri),
                Some(static_headers),
                Some(template_headers),
                Some((payload_prefix, payload_suffix)),
            ) => Ok(ValidatedHttpSink {
                batch_settings,
                encoder,
                payload_prefix,
                payload_suffix,
                static_headers,
                template_headers,
                uri,
            }),
            _ => Err(errors),
        }
    }
}

#[async_trait]
#[typetag::serde(name = "http")]
impl SinkConfig for HttpSinkConfig {
    async fn build(&self, cx: SinkContext) -> crate::Result<(VectorSink, Healthcheck)> {
        let validated = self.validate().map_err(|errors| errors.join("; "))?;
        self.build_with_component_type(cx, Self::NAME, validated)
            .await
    }

    fn confinement_config(&self) -> Option<&crate::template::ConfinementConfig> {
        Some(&self.confinement)
    }

    fn input(&self) -> Input {
        Input::new(self.encoding.config().1.input_type())
    }

    fn files_to_watch(&self) -> Vec<&PathBuf> {
        let mut files = Vec::new();
        if let Some(tls) = &self.tls {
            if let Some(crt_file) = &tls.crt_file {
                files.push(crt_file)
            }
            if let Some(key_file) = &tls.key_file {
                files.push(key_file)
            }
        };
        files
    }

    fn acknowledgements(&self) -> &AcknowledgementsConfig {
        &self.acknowledgements
    }

    fn validate_structure(&self) -> std::result::Result<(), Vec<String>> {
        self.validate().map(|_| ())
    }
}

impl HttpSinkConfig {
    /// Sink construction from values derived by validation. `component_name` is kept alongside the
    /// corresponding validator so wrapper sinks can preserve their component type in confinement
    /// diagnostics.
    pub(crate) async fn build_with_component_type(
        &self,
        cx: SinkContext,
        _component_name: &'static str,
        validated: ValidatedHttpSink,
    ) -> crate::Result<(VectorSink, Healthcheck)> {
        let ValidatedHttpSink {
            batch_settings,
            encoder,
            payload_prefix,
            payload_suffix,
            static_headers,
            template_headers,
            uri,
        } = validated;

        let encoder = match encoder {
            Some(encoder) => encoder,
            None => self.build_encoder()?,
        };
        let transformer = self.encoding.transformer();

        let client = self.build_http_client(&cx)?;

        let healthcheck = match cx.healthcheck.uri {
            Some(healthcheck_uri) => {
                healthcheck(healthcheck_uri, self.auth.clone(), client.clone()).boxed()
            }
            None => future::ok(()).boxed(),
        };

        let content_type = {
            use Framer::*;
            use Serializer::*;
            match (encoder.serializer(), encoder.framer()) {
                (RawMessage(_) | Text(_), _) => Some(CONTENT_TYPE_TEXT.to_owned()),
                (Json(_), NewlineDelimited(_)) => Some(CONTENT_TYPE_NDJSON.to_owned()),
                (Json(_), CharacterDelimited(CharacterDelimitedEncoder { delimiter: b',' })) => {
                    Some(CONTENT_TYPE_JSON.to_owned())
                }
                #[cfg(feature = "codecs-opentelemetry")]
                (Otlp(_), _) => Some("application/x-protobuf".to_owned()),
                _ => None,
            }
        };

        let request_builder = HttpRequestBuilder {
            encoder: HttpEncoder::new(encoder, transformer, payload_prefix, payload_suffix),
            compression: self.compression,
        };

        let content_encoding = self.compression.is_compressed().then(|| {
            self.compression
                .content_encoding()
                .expect("Encoding should be specified for compression.")
                .to_string()
        });

        let http_sink_request_builder = HttpSinkRequestBuilder::new(
            self.method,
            self.auth.clone(),
            static_headers,
            content_type,
            content_encoding,
        );

        let service = match &self.auth {
            #[cfg(feature = "aws-core")]
            Some(Auth::Aws { auth, service }) => {
                let default_region = crate::aws::region_provider(&ProxyConfig::default(), None)?
                    .region()
                    .await;
                let region = (match &auth {
                    AwsAuthentication::AccessKey { region, .. } => region.clone(),
                    AwsAuthentication::File { .. } => None,
                    AwsAuthentication::Role { region, .. } => region.clone(),
                    AwsAuthentication::Default { region, .. } => region.clone(),
                })
                .map_or(default_region, |r| Some(Region::new(r.to_string())))
                .expect("Region must be specified");

                HttpService::new_with_sig_v4(
                    client,
                    http_sink_request_builder,
                    SigV4Config {
                        shared_credentials_provider: auth
                            .credentials_provider(region.clone(), &ProxyConfig::default(), None)
                            .await?,
                        region: region.clone(),
                        service: service.clone(),
                    },
                )
            }
            _ => HttpService::new(client, http_sink_request_builder),
        };

        let request_limits = self.request.tower.into_settings();

        let service = ServiceBuilder::new()
            .settings(
                request_limits,
                http_response_retry_logic(self.retry_strategy.clone()),
            )
            .service(service);

        let sink = HttpSink::new(
            service,
            uri,
            template_headers,
            batch_settings,
            request_builder,
        );

        Ok((VectorSink::from_event_streamsink(sink), healthcheck))
    }
}

#[cfg(test)]
mod tests {
    use vector_lib::codecs::encoding::format::JsonSerializerOptions;
    use vector_lib::codecs::{JsonSerializerConfig, MetricTagValues};

    use super::*;
    use crate::codecs::Transformer;
    use crate::components::validation::prelude::*;
    use crate::template::{ConfinementConfig, Template};

    impl ValidatableComponent for HttpSinkConfig {
        fn validation_configuration() -> ValidationConfiguration {
            use std::str::FromStr;

            use vector_lib::{
                codecs::{JsonSerializerConfig, MetricTagValues},
                config::LogNamespace,
            };

            let endpoint = "http://127.0.0.1:9000/endpoint";
            let uri = UriSerde::from_str(endpoint).expect("should never fail to parse");

            let config = HttpSinkConfig {
                uri: Template::try_from(endpoint).expect("should never fail to parse"),
                method: HttpMethod::Post,
                encoding: EncodingConfigWithFraming::new(
                    None,
                    JsonSerializerConfig::new(
                        MetricTagValues::Full,
                        JsonSerializerOptions::default(),
                    )
                    .into(),
                    Transformer::default(),
                ),
                auth: None,
                compression: Compression::default(),
                batch: BatchConfig::default(),
                request: RequestConfig::default(),
                tls: None,
                acknowledgements: AcknowledgementsConfig::default(),
                payload_prefix: String::new(),
                payload_suffix: String::new(),
                retry_strategy: RetryStrategy::default(),
                confinement: ConfinementConfig::default(),
            };

            let external_resource = ExternalResource::new(
                ResourceDirection::Push,
                HttpResourceConfig::from_parts(uri.uri, Some(config.method.into())),
                config.encoding.clone(),
            );

            ValidationConfiguration::from_sink(
                Self::NAME,
                LogNamespace::Legacy,
                vec![ComponentTestCaseConfig::from_sink(
                    config,
                    None,
                    Some(external_resource),
                )],
            )
        }
    }

    register_validatable_component!(HttpSinkConfig);

    #[test]
    fn validate_yields_confined_uri_headers_and_encoder() {
        use crate::event::Event;
        use vector_lib::event::LogEvent;
        use vrl::event_path;

        let mut headers = BTreeMap::new();
        headers.insert("X-Static".to_string(), "static".to_string());
        headers.insert("X-Tenant".to_string(), "tenant-{{ tenant }}".to_string());

        let config = HttpSinkConfig {
            uri: Template::try_from("https://example.com/ingest/{{ path }}").unwrap(),
            method: HttpMethod::default(),
            encoding: EncodingConfigWithFraming::new(
                None,
                JsonSerializerConfig::new(MetricTagValues::Full, JsonSerializerOptions::default())
                    .into(),
                Transformer::default(),
            ),
            auth: None,
            compression: Compression::default(),
            batch: BatchConfig::default(),
            request: RequestConfig {
                headers,
                ..Default::default()
            },
            tls: None,
            acknowledgements: AcknowledgementsConfig::default(),
            payload_prefix: String::new(),
            payload_suffix: String::new(),
            retry_strategy: RetryStrategy::default(),
            confinement: ConfinementConfig::default(),
        };

        let validated = config.validate().unwrap();
        assert!(validated.encoder.is_some());
        assert!(
            validated
                .static_headers
                .keys()
                .any(|name| name.inner().as_str() == "x-static")
        );

        let mut event = Event::Log(LogEvent::from("test"));
        event.as_mut_log().insert(event_path!("path"), "ok");
        event.as_mut_log().insert(event_path!("tenant"), "acme");

        assert_eq!(
            validated.uri.render_string(&event).unwrap(),
            "https://example.com/ingest/ok"
        );
        assert_eq!(
            validated
                .template_headers
                .get("X-Tenant")
                .unwrap()
                .render_string(&event)
                .unwrap(),
            "tenant-acme"
        );
    }

    #[test]
    fn confinement_rejects_unconfined_uri() {
        let template: Template = "{{ endpoint }}".try_into().unwrap();
        let err = template
            .confine(&ConfinementConfig::default(), "http", "uri")
            .unwrap_err();
        assert!(
            err.to_string().contains("no literal string prefix"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn confinement_opt_out_allows_unconfined_uri() {
        let cfg = ConfinementConfig {
            dangerously_allow_unconfined_template_resolution: true,
        };
        let template: Template = "{{ endpoint }}".try_into().unwrap();
        assert!(template.confine(&cfg, "http", "uri").is_ok());
    }

    #[test]
    fn confinement_blocks_host_redirect_at_render() {
        use crate::event::Event;
        use vector_lib::event::LogEvent;
        use vrl::event_path;

        let template: Template = "https://logs.example.com/ingest/{{ tenant }}"
            .try_into()
            .unwrap();
        let template = template
            .confine(&ConfinementConfig::default(), "http", "uri")
            .unwrap();

        // Attacker tries to redirect to a different host via the tenant field.
        let mut event = Event::Log(LogEvent::from("x"));
        event
            .as_mut_log()
            .insert(event_path!("tenant"), "../../evil.com/steal?data=");
        assert!(template.render_string(&event).is_err());
    }

    #[test]
    fn validate_structure_rejects_invalid_static_uri() {
        // Use a URI with invalid characters that http::Uri will reject
        let config = HttpSinkConfig {
            uri: Template::try_from("http://").unwrap(),
            method: HttpMethod::default(),
            encoding: EncodingConfigWithFraming::new(
                None,
                JsonSerializerConfig::new(MetricTagValues::Full, JsonSerializerOptions::default())
                    .into(),
                Transformer::default(),
            ),
            auth: None,
            compression: Compression::default(),
            batch: BatchConfig::default(),
            request: RequestConfig::default(),
            tls: None,
            acknowledgements: AcknowledgementsConfig::default(),
            payload_prefix: String::new(),
            payload_suffix: String::new(),
            retry_strategy: RetryStrategy::default(),
            confinement: ConfinementConfig::default(),
        };

        let errors = config.validate_structure().unwrap_err();
        assert!(
            errors.iter().any(|e| e.contains("invalid URI")),
            "unexpected errors: {:?}",
            errors
        );
    }

    #[test]
    fn validate_structure_allows_valid_static_uri() {
        let config = HttpSinkConfig {
            uri: Template::try_from("https://example.com/endpoint").unwrap(),
            method: HttpMethod::default(),
            encoding: EncodingConfigWithFraming::new(
                None,
                JsonSerializerConfig::new(MetricTagValues::Full, JsonSerializerOptions::default())
                    .into(),
                Transformer::default(),
            ),
            auth: None,
            compression: Compression::default(),
            batch: BatchConfig::default(),
            request: RequestConfig::default(),
            tls: None,
            acknowledgements: AcknowledgementsConfig::default(),
            payload_prefix: String::new(),
            payload_suffix: String::new(),
            retry_strategy: RetryStrategy::default(),
            confinement: ConfinementConfig::default(),
        };

        config.validate_structure().unwrap();
    }

    #[test]
    fn validate_structure_rejects_malformed_headers() {
        let mut headers = BTreeMap::new();
        headers.insert("Invalid-Header-Name\n".to_string(), "value".to_string());

        let config = HttpSinkConfig {
            uri: Template::try_from("https://example.com").unwrap(),
            method: HttpMethod::default(),
            encoding: EncodingConfigWithFraming::new(
                None,
                JsonSerializerConfig::new(MetricTagValues::Full, JsonSerializerOptions::default())
                    .into(),
                Transformer::default(),
            ),
            auth: None,
            compression: Compression::default(),
            batch: BatchConfig::default(),
            request: RequestConfig {
                headers,
                ..Default::default()
            },
            tls: None,
            acknowledgements: AcknowledgementsConfig::default(),
            payload_prefix: String::new(),
            payload_suffix: String::new(),
            retry_strategy: RetryStrategy::default(),
            confinement: ConfinementConfig::default(),
        };

        let errors = config.validate_structure().unwrap_err();
        assert!(
            errors.iter().any(|e| e.contains("headers")),
            "unexpected errors: {:?}",
            errors
        );
    }

    #[test]
    fn validate_structure_rejects_auth_header_with_auth_config() {
        let mut headers = BTreeMap::new();
        headers.insert("Authorization".to_string(), "Bearer token".to_string());

        let config = HttpSinkConfig {
            uri: Template::try_from("https://example.com").unwrap(),
            method: HttpMethod::default(),
            encoding: EncodingConfigWithFraming::new(
                None,
                JsonSerializerConfig::new(MetricTagValues::Full, JsonSerializerOptions::default())
                    .into(),
                Transformer::default(),
            ),
            auth: Some(crate::http::Auth::Bearer {
                token: "test".to_string().into(),
            }),
            compression: Compression::default(),
            batch: BatchConfig::default(),
            request: RequestConfig {
                headers,
                ..Default::default()
            },
            tls: None,
            acknowledgements: AcknowledgementsConfig::default(),
            payload_prefix: String::new(),
            payload_suffix: String::new(),
            retry_strategy: RetryStrategy::default(),
            confinement: ConfinementConfig::default(),
        };

        let errors = config.validate_structure().unwrap_err();
        assert!(
            errors.iter().any(|e| e.contains("Authorization")),
            "unexpected errors: {:?}",
            errors
        );
    }

    #[test]
    fn validate_structure_rejects_invalid_batch_settings() {
        let mut batch = BatchConfig::default();
        batch.max_events = Some(0);

        let config = HttpSinkConfig {
            uri: Template::try_from("https://example.com").unwrap(),
            method: HttpMethod::default(),
            encoding: EncodingConfigWithFraming::new(
                None,
                JsonSerializerConfig::new(MetricTagValues::Full, JsonSerializerOptions::default())
                    .into(),
                Transformer::default(),
            ),
            auth: None,
            compression: Compression::default(),
            batch,
            request: RequestConfig::default(),
            tls: None,
            acknowledgements: AcknowledgementsConfig::default(),
            payload_prefix: String::new(),
            payload_suffix: String::new(),
            retry_strategy: RetryStrategy::default(),
            confinement: ConfinementConfig::default(),
        };

        let errors = config.validate_structure().unwrap_err();
        assert!(
            errors.iter().any(|e| e.contains("batch")),
            "unexpected errors: {:?}",
            errors
        );
    }

    #[test]
    fn validate_structure_rejects_invalid_payload_wrapper() {
        use crate::codecs::Transformer;
        use vector_lib::codecs::encoding::FramingConfig;
        use vector_lib::codecs::encoding::format::JsonSerializerOptions;
        use vector_lib::codecs::{CharacterDelimitedEncoderConfig, JsonSerializerConfig};

        // JSON serializer with character-delimited (comma) framing
        // This combination triggers payload wrapper validation
        let encoding = EncodingConfigWithFraming::new(
            Some(FramingConfig::CharacterDelimited(
                CharacterDelimitedEncoderConfig::new(b','),
            )),
            JsonSerializerConfig::new(MetricTagValues::Full, JsonSerializerOptions::default())
                .into(),
            Transformer::default(),
        );

        let config = HttpSinkConfig {
            uri: Template::try_from("https://example.com").unwrap(),
            method: HttpMethod::default(),
            encoding,
            auth: None,
            compression: Compression::default(),
            batch: BatchConfig::default(),
            request: RequestConfig::default(),
            tls: None,
            acknowledgements: AcknowledgementsConfig::default(),
            payload_prefix: "{\"data\":".to_string(), // invalid: needs closing brace
            payload_suffix: String::new(),
            retry_strategy: RetryStrategy::default(),
            confinement: ConfinementConfig::default(),
        };

        let errors = config.validate_structure().unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| e.contains("payload_prefix") || e.contains("payload_suffix")),
            "unexpected errors: {:?}",
            errors
        );
    }

    #[test]
    fn validate_structure_rejects_duplicate_credentials() {
        // URI with embedded basic auth, plus auth configured
        let config = HttpSinkConfig {
            uri: Template::try_from("https://user:pass@example.com/endpoint").unwrap(),
            method: HttpMethod::default(),
            encoding: EncodingConfigWithFraming::new(
                None,
                JsonSerializerConfig::new(MetricTagValues::Full, JsonSerializerOptions::default())
                    .into(),
                Transformer::default(),
            ),
            auth: Some(crate::http::Auth::Bearer {
                token: "test".to_string().into(),
            }),
            compression: Compression::default(),
            batch: BatchConfig::default(),
            request: RequestConfig::default(),
            tls: None,
            acknowledgements: AcknowledgementsConfig::default(),
            payload_prefix: String::new(),
            payload_suffix: String::new(),
            retry_strategy: RetryStrategy::default(),
            confinement: ConfinementConfig::default(),
        };

        let errors = config.validate_structure().unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| e.contains("authorization") || e.contains("credentials")),
            "unexpected errors: {:?}",
            errors
        );
    }

    #[test]
    fn validate_structure_rejects_non_http_scheme() {
        // FTP scheme should be rejected
        let config = HttpSinkConfig {
            uri: Template::try_from("ftp://example.com/endpoint").unwrap(),
            method: HttpMethod::default(),
            encoding: EncodingConfigWithFraming::new(
                None,
                JsonSerializerConfig::new(MetricTagValues::Full, JsonSerializerOptions::default())
                    .into(),
                Transformer::default(),
            ),
            auth: None,
            compression: Compression::default(),
            batch: BatchConfig::default(),
            request: RequestConfig::default(),
            tls: None,
            acknowledgements: AcknowledgementsConfig::default(),
            payload_prefix: String::new(),
            payload_suffix: String::new(),
            retry_strategy: RetryStrategy::default(),
            confinement: ConfinementConfig::default(),
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

    #[test]
    fn validate_structure_allows_at_in_path_of_dynamic_uri() {
        // @ in path should not trigger embedded credentials check (only authority should be checked)
        let config = HttpSinkConfig {
            uri: Template::try_from("https://api.example.com/users/{{ id }}").unwrap(),
            method: HttpMethod::default(),
            encoding: EncodingConfigWithFraming::new(
                None,
                JsonSerializerConfig::new(MetricTagValues::Full, JsonSerializerOptions::default())
                    .into(),
                Transformer::default(),
            ),
            auth: Some(crate::http::Auth::Bearer {
                token: "test".to_string().into(),
            }),
            compression: Compression::default(),
            batch: BatchConfig::default(),
            request: RequestConfig::default(),
            tls: None,
            acknowledgements: AcknowledgementsConfig::default(),
            payload_prefix: String::new(),
            payload_suffix: String::new(),
            retry_strategy: RetryStrategy::default(),
            confinement: ConfinementConfig::default(),
        };

        // Should pass because @ is in the path, not the authority
        config.validate_structure().unwrap();
    }
}
