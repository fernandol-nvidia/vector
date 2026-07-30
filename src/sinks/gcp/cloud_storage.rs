use std::{collections::HashMap, convert::TryFrom, io};

use bytes::Bytes;
use chrono::{FixedOffset, Utc};
use http::{
    Uri,
    header::{HeaderName, HeaderValue},
};
use indoc::indoc;
use tower::ServiceBuilder;
use uuid::Uuid;
use vector_lib::{
    TimeZone,
    codecs::encoding::Framer,
    configurable::configurable_component,
    event::{EventFinalizers, Finalizable},
    request_metadata::RequestMetadata,
    stream::BatcherSettings,
};

use crate::{
    codecs::{Encoder, EncodingConfigWithFraming, SinkType, Transformer},
    config::{
        AcknowledgementsConfig, DataType, GenerateConfig, Input, SinkConfig, SinkContext,
        ValidateSink,
    },
    event::Event,
    gcp::{GcpAuthConfig, GcpAuthenticator, Scope},
    http::HttpClient,
    serde::json::to_string,
    sinks::{
        Healthcheck, VectorSink,
        gcs_common::{
            config::{
                GcsPredefinedAcl, GcsRetryLogic, GcsStorageClass, build_healthcheck,
                default_endpoint,
            },
            service::{GcsRequest, GcsRequestSettings, GcsService},
            sink::GcsSink,
        },
        util::{
            BulkSizeBasedDefaultBatchSettings, Compression, RequestBuilder, ServiceBuilderExt,
            TowerRequestConfig, batch::BatchConfig, metadata::RequestMetadataBuilder,
            partitioner::KeyPartitioner, request_builder::EncodeResult,
            service::TowerRequestConfigDefaults, timezone_to_offset,
        },
    },
    template::{ConfinedTemplate, ConfinementConfig, Template},
    tls::{TlsConfig, TlsSettings},
};

#[derive(Clone, Copy, Debug)]
pub struct GcsTowerRequestConfigDefaults;

impl TowerRequestConfigDefaults for GcsTowerRequestConfigDefaults {
    const RATE_LIMIT_NUM: u64 = 1_000;
}

/// Configuration for the `gcp_cloud_storage` sink.
#[configurable_component(sink(
    "gcp_cloud_storage",
    "Store observability events in GCP Cloud Storage."
))]
#[derive(Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct GcsSinkConfig {
    /// The GCS bucket name.
    #[configurable(metadata(docs::examples = "my-bucket"))]
    bucket: String,

    /// The Predefined ACL to apply to created objects.
    ///
    /// For more information, see [Predefined ACLs][predefined_acls].
    ///
    /// [predefined_acls]: https://cloud.google.com/storage/docs/access-control/lists#predefined-acl
    acl: Option<GcsPredefinedAcl>,

    /// The storage class for created objects.
    ///
    /// For more information, see the [storage classes][storage_classes] documentation.
    ///
    /// [storage_classes]: https://cloud.google.com/storage/docs/storage-classes
    storage_class: Option<GcsStorageClass>,

    /// The set of metadata `key:value` pairs for the created objects.
    ///
    /// For more information, see the [custom metadata][custom_metadata] documentation.
    ///
    /// [custom_metadata]: https://cloud.google.com/storage/docs/metadata#custom-metadata
    #[configurable(metadata(docs::additional_props_description = "A key/value pair."))]
    #[configurable(metadata(docs::advanced))]
    metadata: Option<HashMap<String, String>>,

    /// A prefix to apply to all object keys.
    ///
    /// Prefixes are useful for partitioning objects, such as by creating an object key that
    /// stores objects under a particular directory. If using a prefix for this purpose, it must end
    /// in `/` in order to act as a directory path. A trailing `/` is **not** automatically added.
    #[configurable(metadata(docs::templateable))]
    #[configurable(metadata(
        docs::examples = "date=%F/",
        docs::examples = "date=%F/hour=%H/",
        docs::examples = "year=%Y/month=%m/day=%d/",
        docs::examples = "application_id={{ application_id }}/date=%F/"
    ))]
    #[configurable(metadata(docs::advanced))]
    key_prefix: Option<String>,

    /// The timestamp format for the time component of the object key.
    ///
    /// By default, object keys are appended with a timestamp that reflects when the objects are
    /// sent to S3, such that the resulting object key is functionally equivalent to joining the key
    /// prefix with the formatted timestamp, such as `date=2022-07-18/1658176486`.
    ///
    /// This would represent a `key_prefix` set to `date=%F/` and the timestamp of Mon Jul 18 2022
    /// 20:34:44 GMT+0000, with the `filename_time_format` being set to `%s`, which renders
    /// timestamps in seconds since the Unix epoch.
    ///
    /// Supports the common [`strftime`][chrono_strftime_specifiers] specifiers found in most
    /// languages.
    ///
    /// When set to an empty string, no timestamp is appended to the key prefix.
    ///
    /// [chrono_strftime_specifiers]: https://docs.rs/chrono/latest/chrono/format/strftime/index.html#specifiers
    #[serde(default = "default_time_format")]
    #[configurable(metadata(docs::advanced))]
    filename_time_format: String,

    /// Whether or not to append a UUID v4 token to the end of the object key.
    ///
    /// The UUID is appended to the timestamp portion of the object key, such that if the object key
    /// generated is `date=2022-07-18/1658176486`, setting this field to `true` results
    /// in an object key that looks like `date=2022-07-18/1658176486-30f6652c-71da-4f9f-800d-a1189c47c547`.
    ///
    /// This ensures there are no name collisions, and can be useful in high-volume workloads where
    /// object keys must be unique.
    #[serde(default = "crate::serde::default_true")]
    #[configurable(metadata(docs::advanced))]
    filename_append_uuid: bool,

    /// The filename extension to use in the object key.
    ///
    /// If not specified, the extension is determined by the compression scheme used.
    #[configurable(metadata(docs::advanced))]
    filename_extension: Option<String>,

    #[serde(flatten)]
    encoding: EncodingConfigWithFraming,

    /// Compression configuration.
    ///
    /// All compression algorithms use the default compression level unless otherwise specified.
    ///
    /// Some cloud storage API clients and browsers handle decompression transparently, so
    /// depending on how they are accessed, files may not always appear to be compressed.
    #[configurable(derived)]
    #[serde(default)]
    compression: Compression,

    /// Overrides the MIME type of the created objects.
    ///
    /// Directly comparable to the `Content-Type` HTTP header.
    ///
    /// If not specified, defaults to the encoder's content type.
    #[configurable(metadata(
        docs::examples = "text/plain; charset=utf-8",
        docs::examples = "application/gzip"
    ))]
    content_type: Option<String>,

    /// Overrides what content encoding has been applied to the object.
    ///
    /// Directly comparable to the `Content-Encoding` HTTP header.
    ///
    /// If not specified, the compression scheme used dictates this value.
    #[configurable(metadata(docs::examples = "gzip", docs::examples = "zstd"))]
    content_encoding: Option<String>,

    /// Sets the `Cache-Control` header for the created objects.
    ///
    /// Directly comparable to the `Cache-Control` HTTP header.
    #[configurable(metadata(docs::examples = "no-transform"))]
    cache_control: Option<String>,

    #[configurable(derived)]
    #[serde(default)]
    batch: BatchConfig<BulkSizeBasedDefaultBatchSettings>,

    /// API endpoint for Google Cloud Storage
    #[configurable(metadata(docs::examples = "http://localhost:9000"))]
    #[configurable(validation(format = "uri"))]
    #[serde(default = "default_endpoint")]
    endpoint: String,

    #[configurable(derived)]
    #[serde(default)]
    request: TowerRequestConfig<GcsTowerRequestConfigDefaults>,

    #[serde(flatten)]
    auth: GcpAuthConfig,

    #[configurable(derived)]
    tls: Option<TlsConfig>,

    #[configurable(derived)]
    #[serde(
        default,
        deserialize_with = "crate::serde::bool_or_struct",
        skip_serializing_if = "crate::serde::is_default"
    )]
    acknowledgements: AcknowledgementsConfig,

    #[configurable(derived)]
    #[serde(default)]
    pub timezone: Option<TimeZone>,

    #[serde(flatten)]
    pub confinement: ConfinementConfig,
}

fn default_time_format() -> String {
    "%s".to_string()
}

#[cfg(test)]
fn default_config(encoding: EncodingConfigWithFraming) -> GcsSinkConfig {
    GcsSinkConfig {
        bucket: Default::default(),
        acl: Default::default(),
        storage_class: Default::default(),
        metadata: Default::default(),
        key_prefix: Default::default(),
        filename_time_format: default_time_format(),
        filename_append_uuid: true,
        filename_extension: Default::default(),
        content_type: Default::default(),
        content_encoding: Default::default(),
        cache_control: Default::default(),
        encoding,
        compression: Compression::gzip_default(),
        batch: Default::default(),
        endpoint: default_endpoint(),
        request: Default::default(),
        auth: Default::default(),
        tls: Default::default(),
        acknowledgements: Default::default(),
        timezone: Default::default(),
        confinement: ConfinementConfig::default(),
    }
}

impl GenerateConfig for GcsSinkConfig {
    fn generate_config() -> serde_json::Value {
        toml::from_str(indoc! {r#"
            bucket = "my-bucket"
            credentials_path = "/path/to/credentials.json"
            framing.method = "newline_delimited"
            encoding.codec = "json"
        "#})
        .unwrap()
    }
}

/// Values derived while validating [`GcsSinkConfig`], consumed by its `build`.
///
/// The fields are private, so the only way to obtain the confined key prefix, parsed endpoint
/// protocol, request header values, and batcher settings the sink uses is
/// [`ValidateSink::validate`].
#[derive(Debug)]
pub struct ValidatedGcsSink {
    key_prefix: ConfinedTemplate,
    batch_settings: BatcherSettings,
    base_url: String,
    protocol: &'static str,
    content_type: Option<HeaderValue>,
    content_encoding: Option<HeaderValue>,
    cache_control: Option<HeaderValue>,
    metadata_headers: Vec<(HeaderName, HeaderValue)>,
}

impl ValidateSink for GcsSinkConfig {
    type Validated = ValidatedGcsSink;

    fn validate(&self) -> std::result::Result<Self::Validated, Vec<String>> {
        let mut errors = Vec::new();

        let key_prefix = Template::try_from(self.key_prefix.as_deref().unwrap_or("date=%F/"))
            .map_err(|e| format!("key_prefix: {e}"))
            .and_then(|tpl| {
                tpl.confine(&self.confinement, Self::NAME, "key_prefix")
                    .map_err(|e| e.to_string())
            })
            .inspect_err(|e| errors.push(e.clone()))
            .ok();

        let content_type = self
            .content_type
            .as_deref()
            .map(HeaderValue::from_str)
            .transpose()
            .inspect_err(|e| errors.push(format!("content_type: invalid header value: {e}")))
            .ok()
            .flatten();

        let content_encoding = match &self.content_encoding {
            Some(content_encoding) => HeaderValue::from_str(content_encoding)
                .map(Some)
                .inspect_err(|e| {
                    errors.push(format!("content_encoding: invalid header value: {e}"));
                })
                .ok()
                .flatten(),
            None => self
                .compression
                .content_encoding()
                .map(|content_encoding| HeaderValue::from_str(&to_string(content_encoding)))
                .transpose()
                .inspect_err(|e| {
                    errors.push(format!("content_encoding: invalid header value: {e}"));
                })
                .ok()
                .flatten(),
        };

        let cache_control = self
            .cache_control
            .as_deref()
            .map(HeaderValue::from_str)
            .transpose()
            .inspect_err(|e| errors.push(format!("cache_control: invalid header value: {e}")))
            .ok()
            .flatten();

        let mut metadata_headers = Vec::new();
        if let Some(metadata) = &self.metadata {
            for (name, value) in metadata {
                let header_value = HeaderValue::from_str(value)
                    .inspect_err(|e| {
                        errors.push(format!("metadata.{name}: invalid header value: {e}"));
                    })
                    .ok();
                let header_name = HeaderName::from_bytes(name.as_bytes())
                    .inspect_err(|e| {
                        errors.push(format!("metadata.{name}: invalid header name: {e}"));
                    })
                    .ok();

                if let (Some(header_name), Some(header_value)) = (header_name, header_value) {
                    metadata_headers.push((header_name, header_value));
                }
            }
        }

        let base_url = format!("{}/{}/", self.endpoint, self.bucket);
        let protocol = base_url
            .parse::<Uri>()
            .map_err(|e| format!("endpoint: invalid URL after combining with bucket: {e}"))
            .and_then(|uri| {
                let scheme = uri.scheme().map(|s| s.as_str()).unwrap_or("");
                match scheme {
                    "http" => Ok("http"),
                    "https" => Ok("https"),
                    _ => Err(format!(
                        "endpoint: scheme must be 'http' or 'https', got '{}'",
                        scheme
                    )),
                }
            })
            .inspect_err(|e| errors.push(e.clone()))
            .ok();

        if let Err(e) = self.encoding.validate_structure() {
            errors.push(format!("encoding: {e}"));
        }

        let batch_settings = self
            .batch
            .into_batcher_settings()
            .inspect_err(|e| errors.push(format!("batch: {e}")))
            .ok();

        match (errors.is_empty(), key_prefix, protocol, batch_settings) {
            (true, Some(key_prefix), Some(protocol), Some(batch_settings)) => {
                Ok(ValidatedGcsSink {
                    key_prefix,
                    batch_settings,
                    base_url,
                    protocol,
                    content_type,
                    content_encoding,
                    cache_control,
                    metadata_headers,
                })
            }
            _ => Err(errors),
        }
    }
}

#[async_trait::async_trait]
#[typetag::serde(name = "gcp_cloud_storage")]
impl SinkConfig for GcsSinkConfig {
    fn validate_structure(&self) -> std::result::Result<(), Vec<String>> {
        self.validate().map(|_| ())
    }

    async fn build(&self, cx: SinkContext) -> crate::Result<(VectorSink, Healthcheck)> {
        let validated = self.validate().map_err(|errors| errors.join("; "))?;
        let base_url = validated.base_url.clone();

        let auth = self.auth.build(Scope::DevStorageReadWrite).await?;
        let tls = TlsSettings::from_options(self.tls.as_ref())?;
        let client = HttpClient::new(tls, cx.proxy())?;
        let healthcheck = build_healthcheck(
            self.bucket.clone(),
            client.clone(),
            base_url.clone(),
            auth.clone(),
        )?;
        auth.spawn_regenerate_token();
        let sink = self.build_sink(client, auth, cx, validated)?;
        Ok((sink, healthcheck))
    }

    fn confinement_config(&self) -> Option<&crate::template::ConfinementConfig> {
        Some(&self.confinement)
    }

    fn input(&self) -> Input {
        Input::new(self.encoding.config().1.input_type() & DataType::Log)
    }

    fn acknowledgements(&self) -> &AcknowledgementsConfig {
        &self.acknowledgements
    }
}

impl GcsSinkConfig {
    fn build_sink(
        &self,
        client: HttpClient,
        auth: GcpAuthenticator,
        cx: SinkContext,
        validated: ValidatedGcsSink,
    ) -> crate::Result<VectorSink> {
        let ValidatedGcsSink {
            key_prefix,
            batch_settings,
            base_url,
            protocol,
            content_type,
            content_encoding,
            cache_control,
            metadata_headers,
        } = validated;

        let request = self.request.into_settings();
        let partitioner = KeyPartitioner::new(key_prefix, None);

        let svc = ServiceBuilder::new()
            .settings(request, GcsRetryLogic::default())
            .service(GcsService::new(client, base_url, auth));

        let request_settings = RequestSettings::new(
            self,
            cx,
            content_type,
            content_encoding,
            cache_control,
            metadata_headers,
        )?;

        let sink = GcsSink::new(svc, request_settings, partitioner, batch_settings, protocol);

        Ok(VectorSink::from_event_streamsink(sink))
    }

    /// Test-only shortcut from raw config to a partitioner. `build_sink` builds its partitioner
    /// from the already-validated key prefix instead, so this must not be used on the build path.
    #[cfg(test)]
    fn key_partitioner(&self) -> crate::Result<KeyPartitioner> {
        let ValidatedGcsSink { key_prefix, .. } =
            self.validate().map_err(|errors| errors.join("; "))?;
        Ok(KeyPartitioner::new(key_prefix, None))
    }
}

// Settings required to produce a request that do not change per
// request. All possible values are pre-computed for direct use in
// producing a request.
#[derive(Clone, Debug)]
struct RequestSettings {
    acl: Option<HeaderValue>,
    content_type: HeaderValue,
    content_encoding: Option<HeaderValue>,
    storage_class: HeaderValue,
    cache_control: Option<HeaderValue>,
    headers: Vec<(HeaderName, HeaderValue)>,
    extension: String,
    time_format: String,
    append_uuid: bool,
    encoder: (Transformer, Encoder<Framer>),
    compression: Compression,
    tz_offset: Option<FixedOffset>,
}

impl RequestBuilder<(String, Vec<Event>)> for RequestSettings {
    type Metadata = (String, EventFinalizers);
    type Events = Vec<Event>;
    type Encoder = (Transformer, Encoder<Framer>);
    type Payload = Bytes;
    type Request = GcsRequest;
    type Error = io::Error;

    fn compression(&self) -> Compression {
        self.compression
    }

    fn encoder(&self) -> &Self::Encoder {
        &self.encoder
    }

    fn split_input(
        &self,
        input: (String, Vec<Event>),
    ) -> (Self::Metadata, RequestMetadataBuilder, Self::Events) {
        let (partition_key, mut events) = input;
        let finalizers = events.take_finalizers();
        let builder = RequestMetadataBuilder::from_events(&events);

        ((partition_key, finalizers), builder, events)
    }

    fn build_request(
        &self,
        gcp_metadata: Self::Metadata,
        metadata: RequestMetadata,
        payload: EncodeResult<Self::Payload>,
    ) -> Self::Request {
        let (key, finalizers) = gcp_metadata;
        // TODO: pull the seconds from the last event
        let filename = {
            let seconds = match self.tz_offset {
                Some(offset) => Utc::now().with_timezone(&offset).format(&self.time_format),
                None => Utc::now()
                    .with_timezone(&chrono::Utc)
                    .format(&self.time_format),
            };

            if self.append_uuid {
                let uuid = Uuid::new_v4();
                format!("{}-{}", seconds, uuid.hyphenated())
            } else {
                seconds.to_string()
            }
        };

        let key = format!("{}{}.{}", key, filename, self.extension);
        let body = payload.into_payload();

        GcsRequest {
            key,
            body,
            finalizers,
            settings: GcsRequestSettings {
                acl: self.acl.clone(),
                content_type: self.content_type.clone(),
                content_encoding: self.content_encoding.clone(),
                storage_class: self.storage_class.clone(),
                cache_control: self.cache_control.clone(),
                headers: self.headers.clone(),
            },
            metadata,
        }
    }
}

impl RequestSettings {
    fn new(
        config: &GcsSinkConfig,
        cx: SinkContext,
        content_type: Option<HeaderValue>,
        content_encoding: Option<HeaderValue>,
        cache_control: Option<HeaderValue>,
        metadata_headers: Vec<(HeaderName, HeaderValue)>,
    ) -> crate::Result<Self> {
        let transformer = config.encoding.transformer();
        let (framer, serializer) = config.encoding.build(SinkType::MessageBased)?;
        let encoder = Encoder::<Framer>::new(framer, serializer);
        let acl = config
            .acl
            .map(|acl| HeaderValue::from_str(&to_string(acl)).unwrap());
        let content_type = match content_type {
            Some(content_type) => content_type,
            None => HeaderValue::from_str(encoder.content_type())?,
        };
        let storage_class = config.storage_class.unwrap_or_default();
        let storage_class = HeaderValue::from_str(&to_string(storage_class)).unwrap();
        let extension = config
            .filename_extension
            .clone()
            .unwrap_or_else(|| config.compression.extension().into());
        let time_format = config.filename_time_format.clone();
        let append_uuid = config.filename_append_uuid;
        let offset = config
            .timezone
            .or(cx.globals.timezone)
            .and_then(timezone_to_offset);

        Ok(Self {
            acl,
            content_type,
            content_encoding,
            storage_class,
            cache_control,
            headers: metadata_headers,
            extension,
            time_format,
            append_uuid,
            compression: config.compression,
            encoder: (transformer, encoder),
            tz_offset: offset,
        })
    }
}

#[cfg(test)]
mod tests {
    use futures_util::{future::ready, stream};
    use vector_lib::{
        EstimatedJsonEncodedSizeOf,
        codecs::{
            JsonSerializerConfig, NewlineDelimitedEncoderConfig, TextSerializerConfig,
            encoding::FramingConfig,
        },
        partition::Partitioner,
        request_metadata::GroupedCountByteSize,
    };
    use vrl::event_path;

    use super::*;
    use crate::{
        event::LogEvent,
        template::{ConfinementConfig, Template},
        test_util::{
            components::{SINK_TAGS, run_and_assert_sink_compliance},
            http::{always_200_response, spawn_blackhole_http_server},
        },
    };

    #[test]
    fn generate_config() {
        crate::test_util::test_generate_config::<GcsSinkConfig>();
    }

    #[tokio::test]
    async fn component_spec_compliance() {
        let mock_endpoint = spawn_blackhole_http_server(always_200_response).await;

        let context = SinkContext::default();

        let tls = TlsSettings::default();
        let client =
            HttpClient::new(tls, context.proxy()).expect("should not fail to create HTTP client");

        let config = GcsSinkConfig {
            endpoint: mock_endpoint.to_string(),
            bucket: "test-bucket".to_string(),
            ..default_config((None::<FramingConfig>, JsonSerializerConfig::default()).into())
        };
        let validated = config.validate().expect("failed to validate sink");
        let sink = config
            .build_sink(client, GcpAuthenticator::None, context, validated)
            .expect("failed to build sink");

        let event = Event::Log(LogEvent::from("simple message"));
        run_and_assert_sink_compliance(sink, stream::once(ready(event)), &SINK_TAGS).await;
    }

    #[test]
    fn gcs_encode_event_apply_rules() {
        crate::test_util::trace_init();

        let message = "hello world".to_string();
        let mut event = LogEvent::from(message);
        event.insert(event_path!("key"), "value");

        let sink_config = GcsSinkConfig {
            key_prefix: Some("key: {{ key }}".into()),
            ..default_config((None::<FramingConfig>, TextSerializerConfig::default()).into())
        };
        let key = sink_config
            .key_partitioner()
            .unwrap()
            .partition(&Event::Log(event))
            .expect("key wasn't provided");

        assert_eq!(key, "key: value");
    }

    fn request_settings(sink_config: &GcsSinkConfig, context: SinkContext) -> RequestSettings {
        let ValidatedGcsSink {
            content_type,
            content_encoding,
            cache_control,
            metadata_headers,
            ..
        } = sink_config
            .validate()
            .expect("Could not validate request settings");
        RequestSettings::new(
            sink_config,
            context,
            content_type,
            content_encoding,
            cache_control,
            metadata_headers,
        )
        .expect("Could not create request settings")
    }

    fn build_request(extension: Option<&str>, uuid: bool, compression: Compression) -> GcsRequest {
        let context = SinkContext::default();
        let sink_config = GcsSinkConfig {
            key_prefix: Some("key/".into()),
            filename_time_format: "date".into(),
            filename_extension: extension.map(Into::into),
            filename_append_uuid: uuid,
            compression,
            ..default_config(
                (
                    Some(NewlineDelimitedEncoderConfig::new()),
                    JsonSerializerConfig::default(),
                )
                    .into(),
            )
        };
        let log = LogEvent::default().into();
        let key = sink_config
            .key_partitioner()
            .unwrap()
            .partition(&log)
            .expect("key wasn't provided");

        let mut byte_size = GroupedCountByteSize::new_untagged();
        byte_size.add_event(&log, log.estimated_json_encoded_size_of());

        let request_settings = request_settings(&sink_config, context);
        let (metadata, metadata_request_builder, _events) =
            request_settings.split_input((key, vec![log]));
        let payload = EncodeResult::uncompressed(Bytes::new(), byte_size);
        let request_metadata = metadata_request_builder.build(&payload);

        request_settings.build_request(metadata, request_metadata, payload)
    }

    #[test]
    fn gcs_build_request() {
        let req = build_request(Some("ext"), false, Compression::None);
        assert_eq!(req.key, "key/date.ext".to_string());

        let req = build_request(None, false, Compression::None);
        assert_eq!(req.key, "key/date.log".to_string());

        let req = build_request(None, false, Compression::gzip_default());
        assert_eq!(req.key, "key/date.log.gz".to_string());

        let req = build_request(None, true, Compression::gzip_default());
        assert_ne!(req.key, "key/date.log.gz".to_string());
    }

    #[test]
    fn gcs_content_type_default() {
        let context = SinkContext::default();
        let sink_config = GcsSinkConfig {
            content_type: None,
            ..default_config((None::<FramingConfig>, TextSerializerConfig::default()).into())
        };

        let request_settings = request_settings(&sink_config, context);
        // Should default to encoder's content type which is "text/plain" for text codec
        assert_eq!(
            request_settings.content_type.to_str().unwrap(),
            "text/plain"
        );
    }

    #[test]
    fn gcs_content_type_custom() {
        let context = SinkContext::default();
        let sink_config = GcsSinkConfig {
            content_type: Some("text/plain; charset=utf-8".to_string()),
            ..default_config((None::<FramingConfig>, TextSerializerConfig::default()).into())
        };

        let request_settings = request_settings(&sink_config, context);
        // Should use custom content type
        assert_eq!(
            request_settings.content_type.to_str().unwrap(),
            "text/plain; charset=utf-8"
        );
    }

    #[test]
    fn gcs_content_type_invalid() {
        let sink_config = GcsSinkConfig {
            // Invalid header value with newline character
            content_type: Some("text/plain\nInvalid".to_string()),
            ..default_config((None::<FramingConfig>, TextSerializerConfig::default()).into())
        };

        let result = sink_config.validate();
        // Should return an error, not panic
        assert!(result.is_err());
    }

    #[test]
    fn gcs_content_encoding_default() {
        let context = SinkContext::default();
        let sink_config = GcsSinkConfig {
            content_encoding: None,
            compression: Compression::gzip_default(),
            ..default_config((None::<FramingConfig>, TextSerializerConfig::default()).into())
        };

        let request_settings = request_settings(&sink_config, context);
        // Should default to compression's content encoding which is "gzip"
        assert_eq!(
            request_settings.content_encoding.unwrap().to_str().unwrap(),
            "gzip"
        );
    }

    #[test]
    fn gcs_content_encoding_none_when_no_compression() {
        let context = SinkContext::default();
        let sink_config = GcsSinkConfig {
            content_encoding: None,
            compression: Compression::None,
            ..default_config((None::<FramingConfig>, TextSerializerConfig::default()).into())
        };

        let request_settings = request_settings(&sink_config, context);
        // Should be None when compression is None
        assert!(request_settings.content_encoding.is_none());
    }

    #[test]
    fn gcs_content_encoding_custom() {
        let context = SinkContext::default();
        let sink_config = GcsSinkConfig {
            content_encoding: Some("gzip".to_string()),
            compression: Compression::None,
            ..default_config((None::<FramingConfig>, TextSerializerConfig::default()).into())
        };

        let request_settings = request_settings(&sink_config, context);
        // Should use custom content encoding
        assert_eq!(
            request_settings.content_encoding.unwrap().to_str().unwrap(),
            "gzip"
        );
    }

    #[test]
    fn gcs_content_encoding_invalid() {
        let sink_config = GcsSinkConfig {
            // Invalid header value with newline character
            content_encoding: Some("gzip\nInvalid".to_string()),
            ..default_config((None::<FramingConfig>, TextSerializerConfig::default()).into())
        };

        let result = sink_config.validate();
        // Should return an error, not panic
        assert!(result.is_err());
    }

    #[test]
    fn gcs_content_encoding_empty() {
        let context = SinkContext::default();
        let sink_config = GcsSinkConfig {
            // Empty string to disable content encoding header even with compression
            content_encoding: Some("".to_string()),
            compression: Compression::gzip_default(),
            ..default_config((None::<FramingConfig>, TextSerializerConfig::default()).into())
        };

        let request_settings = request_settings(&sink_config, context);
        // Should use empty content encoding (overriding the compression default)
        assert_eq!(
            request_settings.content_encoding.unwrap().to_str().unwrap(),
            ""
        );
    }

    #[test]
    fn gcs_cache_control_default() {
        let context = SinkContext::default();
        let sink_config = GcsSinkConfig {
            cache_control: None,
            ..default_config((None::<FramingConfig>, TextSerializerConfig::default()).into())
        };

        let request_settings = request_settings(&sink_config, context);
        // Should be None by default
        assert!(request_settings.cache_control.is_none());
    }

    #[test]
    fn gcs_cache_control_custom() {
        let context = SinkContext::default();
        let sink_config = GcsSinkConfig {
            cache_control: Some("no-transform".to_string()),
            ..default_config((None::<FramingConfig>, TextSerializerConfig::default()).into())
        };

        let request_settings = request_settings(&sink_config, context);
        assert_eq!(
            request_settings.cache_control.unwrap().to_str().unwrap(),
            "no-transform"
        );
    }

    #[test]
    fn gcs_cache_control_invalid() {
        let sink_config = GcsSinkConfig {
            // Invalid header value with newline character
            cache_control: Some("no-cache\nInvalid".to_string()),
            ..default_config((None::<FramingConfig>, TextSerializerConfig::default()).into())
        };

        let result = sink_config.validate();
        // Should return an error, not panic
        assert!(result.is_err());
    }

    #[test]
    fn confinement_rejects_unconfined_key_prefix() {
        let config = GcsSinkConfig {
            key_prefix: Some("{{ tenant }}".into()),
            ..default_config((None::<FramingConfig>, TextSerializerConfig::default()).into())
        };
        match config.key_partitioner() {
            Err(err) => assert!(
                err.to_string().contains("no literal string prefix"),
                "unexpected error: {err}"
            ),
            Ok(_) => panic!("expected confinement error"),
        }
    }

    #[test]
    fn confinement_opt_out_allows_unconfined_key_prefix() {
        let config = GcsSinkConfig {
            key_prefix: Some("{{ tenant }}".into()),
            confinement: ConfinementConfig {
                dangerously_allow_unconfined_template_resolution: true,
            },
            ..default_config((None::<FramingConfig>, TextSerializerConfig::default()).into())
        };
        assert!(config.key_partitioner().is_ok());
    }

    #[test]
    fn confinement_blocks_dotdot_escape_at_render() {
        use crate::event::Event;

        let template: Template = "safe/{{ tenant }}/".try_into().unwrap();
        let template = template
            .confine(
                &ConfinementConfig::default(),
                "gcp_cloud_storage",
                "key_prefix",
            )
            .unwrap();
        let mut event = Event::Log(LogEvent::from("x"));
        event
            .as_mut_log()
            .insert(event_path!("tenant"), "../../escape");
        assert!(template.render_string(&event).is_err());
    }

    #[test]
    fn validate_structure_rejects_invalid_content_type() {
        let config = GcsSinkConfig {
            content_type: Some("text/plain\nInvalid".to_string()),
            ..default_config((None::<FramingConfig>, TextSerializerConfig::default()).into())
        };

        let errors = config.validate_structure().unwrap_err();
        assert!(
            errors.iter().any(|e| e.contains("content_type")),
            "unexpected errors: {:?}",
            errors
        );
    }

    #[test]
    fn validate_structure_rejects_invalid_content_encoding() {
        let config = GcsSinkConfig {
            content_encoding: Some("gzip\nInvalid".to_string()),
            ..default_config((None::<FramingConfig>, TextSerializerConfig::default()).into())
        };

        let errors = config.validate_structure().unwrap_err();
        assert!(
            errors.iter().any(|e| e.contains("content_encoding")),
            "unexpected errors: {:?}",
            errors
        );
    }

    #[test]
    fn validate_structure_rejects_invalid_cache_control() {
        let config = GcsSinkConfig {
            cache_control: Some("no-transform\nInvalid".to_string()),
            ..default_config((None::<FramingConfig>, TextSerializerConfig::default()).into())
        };

        let errors = config.validate_structure().unwrap_err();
        assert!(
            errors.iter().any(|e| e.contains("cache_control")),
            "unexpected errors: {:?}",
            errors
        );
    }

    #[test]
    fn validate_structure_rejects_invalid_metadata_value() {
        let mut metadata = std::collections::HashMap::new();
        metadata.insert("key".to_string(), "value\nInvalid".to_string());

        let config = GcsSinkConfig {
            metadata: Some(metadata),
            ..default_config((None::<FramingConfig>, TextSerializerConfig::default()).into())
        };

        let errors = config.validate_structure().unwrap_err();
        assert!(
            errors.iter().any(|e| e.contains("metadata.key")),
            "unexpected errors: {:?}",
            errors
        );
    }

    #[test]
    fn validate_structure_allows_valid_header_fields() {
        let mut metadata = std::collections::HashMap::new();
        metadata.insert("key".to_string(), "valid-value".to_string());

        let config = GcsSinkConfig {
            content_type: Some("text/plain".to_string()),
            content_encoding: Some("gzip".to_string()),
            cache_control: Some("no-transform".to_string()),
            metadata: Some(metadata),
            ..default_config((None::<FramingConfig>, TextSerializerConfig::default()).into())
        };

        config.validate_structure().unwrap();
    }

    #[test]
    fn validate_yields_request_header_values_and_key_prefix() {
        let mut metadata = std::collections::HashMap::new();
        metadata.insert("x-meta-key".to_string(), "valid-value".to_string());

        let config = GcsSinkConfig {
            key_prefix: Some("key/{{ key }}/".into()),
            content_type: Some("text/plain".to_string()),
            content_encoding: Some("gzip".to_string()),
            cache_control: Some("no-transform".to_string()),
            metadata: Some(metadata),
            ..default_config((None::<FramingConfig>, TextSerializerConfig::default()).into())
        };

        let ValidatedGcsSink {
            key_prefix,
            protocol,
            content_type,
            content_encoding,
            cache_control,
            metadata_headers,
            ..
        } = config.validate().unwrap();

        assert_eq!(protocol, "https");
        assert_eq!(content_type.unwrap().to_str().unwrap(), "text/plain");
        assert_eq!(content_encoding.unwrap().to_str().unwrap(), "gzip");
        assert_eq!(cache_control.unwrap().to_str().unwrap(), "no-transform");
        assert_eq!(metadata_headers.len(), 1);
        assert_eq!(metadata_headers[0].0.as_str(), "x-meta-key");
        assert_eq!(metadata_headers[0].1.to_str().unwrap(), "valid-value");

        let mut event = LogEvent::from("message");
        event.insert(event_path!("key"), "value");
        let key = KeyPartitioner::new(key_prefix, None)
            .partition(&Event::Log(event))
            .expect("key wasn't provided");
        assert_eq!(key, "key/value/");
    }

    #[test]
    fn validate_structure_rejects_invalid_metadata_key() {
        let mut metadata = std::collections::HashMap::new();
        metadata.insert("bad\nkey".to_string(), "value".to_string());

        let config = GcsSinkConfig {
            metadata: Some(metadata),
            ..default_config((None::<FramingConfig>, TextSerializerConfig::default()).into())
        };

        let errors = config.validate_structure().unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| e.contains("metadata.bad\nkey") && e.contains("invalid header name")),
            "unexpected errors: {:?}",
            errors
        );
    }

    #[test]
    fn validate_structure_rejects_invalid_endpoint() {
        let config = GcsSinkConfig {
            endpoint: "http://%".to_string(),
            bucket: "my-bucket".to_string(),
            ..default_config((None::<FramingConfig>, TextSerializerConfig::default()).into())
        };

        let errors = config.validate_structure().unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| e.contains("endpoint") && e.contains("invalid URL")),
            "unexpected errors: {:?}",
            errors
        );
    }

    #[test]
    fn validate_structure_rejects_non_http_scheme() {
        let config = GcsSinkConfig {
            endpoint: "ftp://storage.example.com".to_string(),
            bucket: "my-bucket".to_string(),
            ..default_config((None::<FramingConfig>, TextSerializerConfig::default()).into())
        };

        let errors = config.validate_structure().unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| e.contains("endpoint") && e.contains("scheme") && e.contains("http")),
            "unexpected errors: {:?}",
            errors
        );
    }
}
