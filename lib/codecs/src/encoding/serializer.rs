//! Serializer configuration and implementation for encoding structured events as bytes.

use bytes::BytesMut;
use vector_config::configurable_component;
use vector_core::{config::DataType, event::Event, schema};

#[cfg(feature = "arrow")]
use super::format::{ArrowStreamSerializer, ArrowStreamSerializerConfig};
#[cfg(feature = "opentelemetry")]
use super::format::{OtlpSerializer, OtlpSerializerConfig};
#[cfg(feature = "parquet")]
use super::format::{ParquetSerializer, ParquetSerializerConfig};
#[cfg(feature = "syslog")]
use super::format::{SyslogSerializer, SyslogSerializerConfig};
use super::{
    chunking::Chunker,
    format::{
        AvroSerializer, AvroSerializerConfig, AvroSerializerOptions, CefSerializer,
        CefSerializerConfig, CsvSerializer, CsvSerializerConfig, GelfSerializer,
        GelfSerializerConfig, JsonSerializer, JsonSerializerConfig, LogfmtSerializer,
        LogfmtSerializerConfig, NativeJsonSerializer, NativeJsonSerializerConfig, NativeSerializer,
        NativeSerializerConfig, ProtobufSerializer, ProtobufSerializerConfig, RawMessageSerializer,
        RawMessageSerializerConfig, TextSerializer, TextSerializerConfig,
    },
    framing::{
        CharacterDelimitedEncoderConfig, FramingConfig, LengthDelimitedEncoderConfig,
        VarintLengthDelimitedEncoderConfig,
    },
};

/// Serializer configuration.
#[configurable_component]
#[derive(Clone, Debug)]
#[serde(tag = "codec", rename_all = "snake_case")]
#[configurable(metadata(docs::enum_tag_description = "The codec to use for encoding events."))]
pub enum SerializerConfig {
    /// Encodes an event as an [Apache Avro][apache_avro] message.
    ///
    /// [apache_avro]: https://avro.apache.org/
    Avro {
        /// Apache Avro-specific encoder options.
        avro: AvroSerializerOptions,
    },

    /// Encodes an event as a CEF (Common Event Format) formatted message.
    ///
    Cef(
        /// Options for the CEF encoder.
        CefSerializerConfig,
    ),

    /// Encodes an event as a CSV message.
    ///
    /// This codec must be configured with fields to encode.
    ///
    Csv(CsvSerializerConfig),

    /// Encodes an event as a [GELF][gelf] message.
    ///
    /// This codec is experimental for the following reason:
    ///
    /// The GELF specification is more strict than the actual Graylog receiver.
    /// Vector's encoder currently adheres more strictly to the GELF spec, with
    /// the exception that some characters such as `@`  are allowed in field names.
    ///
    /// Other GELF codecs, such as Loki's, use a [Go SDK][implementation] that is maintained
    /// by Graylog and is much more relaxed than the GELF spec.
    ///
    /// Going forward, Vector will use that [Go SDK][implementation] as the reference implementation, which means
    /// the codec might continue to relax the enforcement of the specification.
    ///
    /// [gelf]: https://docs.graylog.org/docs/gelf
    /// [implementation]: https://github.com/Graylog2/go-gelf/blob/v2/gelf/reader.go
    Gelf(GelfSerializerConfig),

    /// Encodes an event as [JSON][json].
    ///
    /// [json]: https://www.json.org/
    Json(JsonSerializerConfig),

    /// Encodes an event as a [logfmt][logfmt] message.
    ///
    /// [logfmt]: https://brandur.org/logfmt
    Logfmt,

    /// Encodes an event in the [native Protocol Buffers format][vector_native_protobuf].
    ///
    /// This codec is **[experimental][experimental]**.
    ///
    /// [vector_native_protobuf]: https://github.com/vectordotdev/vector/blob/master/lib/vector-core/proto/event.proto
    /// [experimental]: https://vector.dev/highlights/2022-03-31-native-event-codecs
    Native,

    /// Encodes an event in the [native JSON format][vector_native_json].
    ///
    /// This codec is **[experimental][experimental]**.
    ///
    /// [vector_native_json]: https://github.com/vectordotdev/vector/blob/master/lib/codecs/tests/data/native_encoding/schema.cue
    /// [experimental]: https://vector.dev/highlights/2022-03-31-native-event-codecs
    NativeJson,

    /// Encodes an event in the [OTLP (OpenTelemetry Protocol)][otlp] format.
    ///
    /// This codec uses protobuf encoding, which is the recommended format for OTLP.
    /// The output is suitable for sending to OTLP-compatible endpoints with
    /// `content-type: application/x-protobuf`.
    ///
    /// [otlp]: https://opentelemetry.io/docs/specs/otlp/
    #[cfg(feature = "opentelemetry")]
    Otlp,

    /// Encodes an event as a [Protobuf][protobuf] message.
    ///
    /// [protobuf]: https://protobuf.dev/
    Protobuf(ProtobufSerializerConfig),

    /// No encoding.
    ///
    /// This encoding uses the `message` field of a log event.
    ///
    /// Be careful if you are modifying your log events (for example, by using a `remap`
    /// transform) and removing the message field while doing additional parsing on it, as this
    /// could lead to the encoding emitting empty strings for the given event.
    RawMessage,

    /// Plain text encoding.
    ///
    /// This encoding uses the `message` field of a log event. For metrics, it uses an
    /// encoding that resembles the Prometheus export format.
    ///
    /// Be careful if you are modifying your log events (for example, by using a `remap`
    /// transform) and removing the message field while doing additional parsing on it, as this
    /// could lead to the encoding emitting empty strings for the given event.
    Text(TextSerializerConfig),

    /// Syslog encoding
    /// RFC 3164 and 5424 are supported
    #[cfg(feature = "syslog")]
    Syslog(SyslogSerializerConfig),
}

impl Default for SerializerConfig {
    fn default() -> Self {
        Self::Json(JsonSerializerConfig::default())
    }
}

/// Batch serializer configuration.
///
/// Only available when the `arrow` feature is enabled (the `parquet` feature
/// implies `arrow`); all batch serializers produce columnar Arrow/Parquet output.
#[cfg(feature = "arrow")]
#[configurable_component]
#[derive(Clone, Debug)]
#[serde(tag = "codec", rename_all = "snake_case")]
#[configurable(metadata(
    docs::enum_tag_description = "The codec to use for batch encoding events."
))]
pub enum BatchSerializerConfig {
    /// Encodes events in [Apache Arrow][apache_arrow] IPC streaming format.
    ///
    /// This is the streaming variant of the Arrow IPC format, which writes
    /// a continuous stream of record batches.
    ///
    /// [apache_arrow]: https://arrow.apache.org/
    #[serde(rename = "arrow_stream")]
    ArrowStream(ArrowStreamSerializerConfig),
    /// Encodes events in [Apache Parquet][apache_parquet] columnar format.
    ///
    /// [apache_parquet]: https://parquet.apache.org/
    #[cfg(feature = "parquet")]
    #[serde(rename = "parquet")]
    Parquet(ParquetSerializerConfig),
}

#[cfg(feature = "arrow")]
impl BatchSerializerConfig {
    /// Build the batch serializer from this configuration.
    pub fn build_batch_serializer(
        &self,
    ) -> Result<super::BatchSerializer, Box<dyn std::error::Error + Send + Sync + 'static>> {
        match self {
            BatchSerializerConfig::ArrowStream(arrow_config) => {
                let serializer = ArrowStreamSerializer::new(arrow_config.clone())?;
                Ok(super::BatchSerializer::Arrow(serializer))
            }
            #[cfg(feature = "parquet")]
            BatchSerializerConfig::Parquet(parquet_config) => {
                let serializer = ParquetSerializer::new(parquet_config.clone())?;
                Ok(super::BatchSerializer::Parquet(Box::new(serializer)))
            }
        }
    }

    /// The data type of events that are accepted by this batch serializer.
    pub fn input_type(&self) -> DataType {
        match self {
            BatchSerializerConfig::ArrowStream(arrow_config) => arrow_config.input_type(),
            #[cfg(feature = "parquet")]
            BatchSerializerConfig::Parquet(parquet_config) => parquet_config.input_type(),
        }
    }

    /// The schema required by the batch serializer.
    pub fn schema_requirement(&self) -> schema::Requirement {
        match self {
            BatchSerializerConfig::ArrowStream(arrow_config) => arrow_config.schema_requirement(),
            #[cfg(feature = "parquet")]
            BatchSerializerConfig::Parquet(parquet_config) => parquet_config.schema_requirement(),
        }
    }
}

impl From<AvroSerializerConfig> for SerializerConfig {
    fn from(config: AvroSerializerConfig) -> Self {
        Self::Avro { avro: config.avro }
    }
}

impl From<CefSerializerConfig> for SerializerConfig {
    fn from(config: CefSerializerConfig) -> Self {
        Self::Cef(config)
    }
}

impl From<CsvSerializerConfig> for SerializerConfig {
    fn from(config: CsvSerializerConfig) -> Self {
        Self::Csv(config)
    }
}

impl From<GelfSerializerConfig> for SerializerConfig {
    fn from(config: GelfSerializerConfig) -> Self {
        Self::Gelf(config)
    }
}

impl From<JsonSerializerConfig> for SerializerConfig {
    fn from(config: JsonSerializerConfig) -> Self {
        Self::Json(config)
    }
}

impl From<LogfmtSerializerConfig> for SerializerConfig {
    fn from(_: LogfmtSerializerConfig) -> Self {
        Self::Logfmt
    }
}

impl From<NativeSerializerConfig> for SerializerConfig {
    fn from(_: NativeSerializerConfig) -> Self {
        Self::Native
    }
}

impl From<NativeJsonSerializerConfig> for SerializerConfig {
    fn from(_: NativeJsonSerializerConfig) -> Self {
        Self::NativeJson
    }
}

#[cfg(feature = "opentelemetry")]
impl From<OtlpSerializerConfig> for SerializerConfig {
    fn from(_: OtlpSerializerConfig) -> Self {
        Self::Otlp
    }
}

impl From<ProtobufSerializerConfig> for SerializerConfig {
    fn from(config: ProtobufSerializerConfig) -> Self {
        Self::Protobuf(config)
    }
}

impl From<RawMessageSerializerConfig> for SerializerConfig {
    fn from(_: RawMessageSerializerConfig) -> Self {
        Self::RawMessage
    }
}

impl From<TextSerializerConfig> for SerializerConfig {
    fn from(config: TextSerializerConfig) -> Self {
        Self::Text(config)
    }
}

impl SerializerConfig {
    /// Validates structural constraints on the serializer configuration that do not require
    /// environment resources (like filesystem I/O or network access).
    ///
    /// This is called during config compilation so errors are reported on both
    /// `vector validate --no-environment` and normal startup/reload.
    ///
    /// # Errors
    ///
    /// If validation does not succeed, an error is returned.
    pub fn validate_structure(
        &self,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        match self {
            // Protobuf requires a valid message_type format but does NOT read the descriptor file.
            // The descriptor file existence check is deferred to the actual build() call.
            SerializerConfig::Protobuf(config) => {
                // Validate message_type is not empty
                if config.protobuf.message_type.is_empty() {
                    return Err("protobuf.message_type must not be empty".into());
                }
                // Validate message_type has a valid format (package.Message)
                // A valid protobuf message type should contain at least one dot separating package and message
                if !config.protobuf.message_type.contains('.') {
                    return Err(format!(
                        "protobuf.message_type '{}' must be a fully qualified name (e.g., 'package.Message')",
                        config.protobuf.message_type
                    ).into());
                }
                // Validate desc_file is not empty (path validation without reading the file)
                if config.protobuf.desc_file.as_os_str().is_empty() {
                    return Err("protobuf.desc_file must not be empty".into());
                }
                Ok(())
            }
            // Avro schema is in config, no I/O required
            SerializerConfig::Avro { avro } => {
                if avro.schema.is_empty() {
                    return Err("avro.schema must not be empty".into());
                }
                Ok(())
            }
            // CSV requires fields to be configured
            SerializerConfig::Csv(config) => config.validate_structure(),
            // CEF requires fields to be configured
            SerializerConfig::Cef(config) => config.validate_structure(),
            // All other serializers have no structural validation requirements
            // that don't involve I/O or external resources
            _ => Ok(()),
        }
    }

    /// Build the `Serializer` from this configuration.
    pub fn build(&self) -> Result<Serializer, Box<dyn std::error::Error + Send + Sync + 'static>> {
        match self {
            SerializerConfig::Avro { avro } => Ok(Serializer::Avro(
                AvroSerializerConfig::new(avro.schema.clone()).build()?,
            )),
            SerializerConfig::Cef(config) => Ok(Serializer::Cef(config.build()?)),
            SerializerConfig::Csv(config) => Ok(Serializer::Csv(config.build()?)),
            SerializerConfig::Gelf(config) => Ok(Serializer::Gelf(config.build())),
            SerializerConfig::Json(config) => Ok(Serializer::Json(config.build())),
            SerializerConfig::Logfmt => Ok(Serializer::Logfmt(LogfmtSerializerConfig.build())),
            SerializerConfig::Native => Ok(Serializer::Native(NativeSerializerConfig.build())),
            SerializerConfig::NativeJson => {
                Ok(Serializer::NativeJson(NativeJsonSerializerConfig.build()))
            }
            #[cfg(feature = "opentelemetry")]
            SerializerConfig::Otlp => {
                Ok(Serializer::Otlp(OtlpSerializerConfig::default().build()?))
            }
            SerializerConfig::Protobuf(config) => Ok(Serializer::Protobuf(config.build()?)),
            SerializerConfig::RawMessage => {
                Ok(Serializer::RawMessage(RawMessageSerializerConfig.build()))
            }
            SerializerConfig::Text(config) => Ok(Serializer::Text(config.build())),
            #[cfg(feature = "syslog")]
            SerializerConfig::Syslog(config) => Ok(Serializer::Syslog(config.build())),
        }
    }

    /// Return an appropriate default framer for the given serializer.
    pub fn default_stream_framing(&self) -> FramingConfig {
        match self {
            // TODO: Technically, Avro messages are supposed to be framed[1] as a vector of
            // length-delimited buffers -- `len` as big-endian 32-bit unsigned integer, followed by
            // `len` bytes -- with a "zero-length buffer" to terminate the overall message... which
            // our length delimited framer obviously will not do.
            //
            // This is OK for now, because the Avro serializer is more ceremonial than anything
            // else, existing to curry serializer config options to Pulsar's native client, not to
            // actually serialize the bytes themselves... but we're still exposing this method and
            // we should do so accurately, even if practically it doesn't need to be.
            //
            // [1]: https://avro.apache.org/docs/1.11.1/specification/_print/#message-framing
            SerializerConfig::Avro { .. } | SerializerConfig::Native => {
                FramingConfig::LengthDelimited(LengthDelimitedEncoderConfig::default())
            }
            #[cfg(feature = "opentelemetry")]
            SerializerConfig::Otlp => FramingConfig::Bytes,
            SerializerConfig::Protobuf(_) => {
                FramingConfig::VarintLengthDelimited(VarintLengthDelimitedEncoderConfig::default())
            }
            SerializerConfig::Cef(_)
            | SerializerConfig::Csv(_)
            | SerializerConfig::Json(_)
            | SerializerConfig::Logfmt
            | SerializerConfig::NativeJson
            | SerializerConfig::RawMessage
            | SerializerConfig::Text(_) => FramingConfig::NewlineDelimited,
            #[cfg(feature = "syslog")]
            SerializerConfig::Syslog(_) => FramingConfig::NewlineDelimited,
            SerializerConfig::Gelf(_) => {
                FramingConfig::CharacterDelimited(CharacterDelimitedEncoderConfig::new(0))
            }
        }
    }

    /// The data type of events that are accepted by this `Serializer`.
    pub fn input_type(&self) -> DataType {
        match self {
            SerializerConfig::Avro { avro } => {
                AvroSerializerConfig::new(avro.schema.clone()).input_type()
            }
            SerializerConfig::Cef(config) => config.input_type(),
            SerializerConfig::Csv(config) => config.input_type(),
            SerializerConfig::Gelf(config) => config.input_type(),
            SerializerConfig::Json(config) => config.input_type(),
            SerializerConfig::Logfmt => LogfmtSerializerConfig.input_type(),
            SerializerConfig::Native => NativeSerializerConfig.input_type(),
            SerializerConfig::NativeJson => NativeJsonSerializerConfig.input_type(),
            #[cfg(feature = "opentelemetry")]
            SerializerConfig::Otlp => OtlpSerializerConfig::default().input_type(),
            SerializerConfig::Protobuf(config) => config.input_type(),
            SerializerConfig::RawMessage => RawMessageSerializerConfig.input_type(),
            SerializerConfig::Text(config) => config.input_type(),
            #[cfg(feature = "syslog")]
            SerializerConfig::Syslog(config) => config.input_type(),
        }
    }

    /// The schema required by the serializer.
    pub fn schema_requirement(&self) -> schema::Requirement {
        match self {
            SerializerConfig::Avro { avro } => {
                AvroSerializerConfig::new(avro.schema.clone()).schema_requirement()
            }
            SerializerConfig::Cef(config) => config.schema_requirement(),
            SerializerConfig::Csv(config) => config.schema_requirement(),
            SerializerConfig::Gelf(config) => config.schema_requirement(),
            SerializerConfig::Json(config) => config.schema_requirement(),
            SerializerConfig::Logfmt => LogfmtSerializerConfig.schema_requirement(),
            SerializerConfig::Native => NativeSerializerConfig.schema_requirement(),
            SerializerConfig::NativeJson => NativeJsonSerializerConfig.schema_requirement(),
            #[cfg(feature = "opentelemetry")]
            SerializerConfig::Otlp => OtlpSerializerConfig::default().schema_requirement(),
            SerializerConfig::Protobuf(config) => config.schema_requirement(),
            SerializerConfig::RawMessage => RawMessageSerializerConfig.schema_requirement(),
            SerializerConfig::Text(config) => config.schema_requirement(),
            #[cfg(feature = "syslog")]
            SerializerConfig::Syslog(config) => config.schema_requirement(),
        }
    }
}

/// Serialize structured events as bytes.
#[derive(Debug, Clone)]
pub enum Serializer {
    /// Uses an `AvroSerializer` for serialization.
    Avro(AvroSerializer),
    /// Uses a `CefSerializer` for serialization.
    Cef(CefSerializer),
    /// Uses a `CsvSerializer` for serialization.
    Csv(CsvSerializer),
    /// Uses a `GelfSerializer` for serialization.
    Gelf(GelfSerializer),
    /// Uses a `JsonSerializer` for serialization.
    Json(JsonSerializer),
    /// Uses a `LogfmtSerializer` for serialization.
    Logfmt(LogfmtSerializer),
    /// Uses a `NativeSerializer` for serialization.
    Native(NativeSerializer),
    /// Uses a `NativeJsonSerializer` for serialization.
    NativeJson(NativeJsonSerializer),
    /// Uses an `OtlpSerializer` for serialization.
    #[cfg(feature = "opentelemetry")]
    Otlp(OtlpSerializer),
    /// Uses a `ProtobufSerializer` for serialization.
    Protobuf(ProtobufSerializer),
    /// Uses a `RawMessageSerializer` for serialization.
    RawMessage(RawMessageSerializer),
    /// Uses a `TextSerializer` for serialization.
    Text(TextSerializer),
    /// Uses a `SyslogSerializer` for serialization.
    #[cfg(feature = "syslog")]
    Syslog(SyslogSerializer),
}

impl Serializer {
    /// Check if the serializer supports encoding an event to JSON via `Serializer::to_json_value`.
    pub fn supports_json(&self) -> bool {
        match self {
            Serializer::Json(_) | Serializer::NativeJson(_) | Serializer::Gelf(_) => true,
            Serializer::Avro(_)
            | Serializer::Cef(_)
            | Serializer::Csv(_)
            | Serializer::Logfmt(_)
            | Serializer::Text(_)
            | Serializer::Native(_)
            | Serializer::Protobuf(_)
            | Serializer::RawMessage(_) => false,
            #[cfg(feature = "syslog")]
            Serializer::Syslog(_) => false,
            #[cfg(feature = "opentelemetry")]
            Serializer::Otlp(_) => false,
        }
    }

    /// Encode event and represent it as JSON value.
    ///
    /// # Panics
    ///
    /// Panics if the serializer does not support encoding to JSON. Call `Serializer::supports_json`
    /// if you need to determine the capability to encode to JSON at runtime.
    pub fn to_json_value(&self, event: Event) -> Result<serde_json::Value, vector_common::Error> {
        match self {
            Serializer::Gelf(serializer) => serializer.to_json_value(event),
            Serializer::Json(serializer) => serializer.to_json_value(event),
            Serializer::NativeJson(serializer) => serializer.to_json_value(event),
            Serializer::Avro(_)
            | Serializer::Cef(_)
            | Serializer::Csv(_)
            | Serializer::Logfmt(_)
            | Serializer::Text(_)
            | Serializer::Native(_)
            | Serializer::Protobuf(_)
            | Serializer::RawMessage(_) => {
                panic!("Serializer does not support JSON")
            }
            #[cfg(feature = "syslog")]
            Serializer::Syslog(_) => {
                panic!("Serializer does not support JSON")
            }
            #[cfg(feature = "opentelemetry")]
            Serializer::Otlp(_) => {
                panic!("Serializer does not support JSON")
            }
        }
    }

    /// Returns the chunking implementation for the serializer, if any is supported.
    pub fn chunker(&self) -> Option<Chunker> {
        match self {
            Serializer::Gelf(gelf) => Some(Chunker::Gelf(gelf.chunker())),
            _ => None,
        }
    }

    /// Returns whether the serializer produces binary output.
    ///
    /// Binary serializers produce raw bytes that should not be interpreted as text,
    /// while text serializers produce UTF-8 encoded strings.
    pub const fn is_binary(&self) -> bool {
        match self {
            Serializer::RawMessage(_)
            | Serializer::Avro(_)
            | Serializer::Native(_)
            | Serializer::Protobuf(_) => true,
            #[cfg(feature = "opentelemetry")]
            Serializer::Otlp(_) => true,
            #[cfg(feature = "syslog")]
            Serializer::Syslog(_) => false,
            Serializer::Cef(_)
            | Serializer::Csv(_)
            | Serializer::Logfmt(_)
            | Serializer::Gelf(_)
            | Serializer::Json(_)
            | Serializer::Text(_)
            | Serializer::NativeJson(_) => false,
        }
    }
}

impl From<AvroSerializer> for Serializer {
    fn from(serializer: AvroSerializer) -> Self {
        Self::Avro(serializer)
    }
}

impl From<CefSerializer> for Serializer {
    fn from(serializer: CefSerializer) -> Self {
        Self::Cef(serializer)
    }
}

impl From<CsvSerializer> for Serializer {
    fn from(serializer: CsvSerializer) -> Self {
        Self::Csv(serializer)
    }
}

impl From<GelfSerializer> for Serializer {
    fn from(serializer: GelfSerializer) -> Self {
        Self::Gelf(serializer)
    }
}

impl From<JsonSerializer> for Serializer {
    fn from(serializer: JsonSerializer) -> Self {
        Self::Json(serializer)
    }
}

impl From<LogfmtSerializer> for Serializer {
    fn from(serializer: LogfmtSerializer) -> Self {
        Self::Logfmt(serializer)
    }
}

impl From<NativeSerializer> for Serializer {
    fn from(serializer: NativeSerializer) -> Self {
        Self::Native(serializer)
    }
}

impl From<NativeJsonSerializer> for Serializer {
    fn from(serializer: NativeJsonSerializer) -> Self {
        Self::NativeJson(serializer)
    }
}

#[cfg(feature = "opentelemetry")]
impl From<OtlpSerializer> for Serializer {
    fn from(serializer: OtlpSerializer) -> Self {
        Self::Otlp(serializer)
    }
}

impl From<ProtobufSerializer> for Serializer {
    fn from(serializer: ProtobufSerializer) -> Self {
        Self::Protobuf(serializer)
    }
}

impl From<RawMessageSerializer> for Serializer {
    fn from(serializer: RawMessageSerializer) -> Self {
        Self::RawMessage(serializer)
    }
}

impl From<TextSerializer> for Serializer {
    fn from(serializer: TextSerializer) -> Self {
        Self::Text(serializer)
    }
}
#[cfg(feature = "syslog")]
impl From<SyslogSerializer> for Serializer {
    fn from(serializer: SyslogSerializer) -> Self {
        Self::Syslog(serializer)
    }
}

impl tokio_util::codec::Encoder<Event> for Serializer {
    type Error = vector_common::Error;

    fn encode(&mut self, event: Event, buffer: &mut BytesMut) -> Result<(), Self::Error> {
        match self {
            Serializer::Avro(serializer) => serializer.encode(event, buffer),
            Serializer::Cef(serializer) => serializer.encode(event, buffer),
            Serializer::Csv(serializer) => serializer.encode(event, buffer),
            Serializer::Gelf(serializer) => serializer.encode(event, buffer),
            Serializer::Json(serializer) => serializer.encode(event, buffer),
            Serializer::Logfmt(serializer) => serializer.encode(event, buffer),
            Serializer::Native(serializer) => serializer.encode(event, buffer),
            Serializer::NativeJson(serializer) => serializer.encode(event, buffer),
            #[cfg(feature = "opentelemetry")]
            Serializer::Otlp(serializer) => serializer.encode(event, buffer),
            Serializer::Protobuf(serializer) => serializer.encode(event, buffer),
            Serializer::RawMessage(serializer) => serializer.encode(event, buffer),
            Serializer::Text(serializer) => serializer.encode(event, buffer),
            #[cfg(feature = "syslog")]
            Serializer::Syslog(serializer) => serializer.encode(event, buffer),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::ProtobufSerializerOptions;
    use std::path::PathBuf;

    #[test]
    fn test_serializer_config_default() {
        // SerializerConfig should default to Json
        let config = SerializerConfig::default();
        assert!(matches!(config, SerializerConfig::Json(_)));
    }

    #[test]
    fn test_serializer_is_binary() {
        // Test that is_binary correctly identifies binary serializers
        let json_config = JsonSerializerConfig::default();
        let json_serializer = Serializer::Json(json_config.build());
        assert!(!json_serializer.is_binary());

        let native_serializer = Serializer::Native(NativeSerializerConfig.build());
        assert!(native_serializer.is_binary());

        let raw_message_serializer = Serializer::RawMessage(RawMessageSerializerConfig.build());
        assert!(raw_message_serializer.is_binary());
    }

    #[test]
    fn test_serializer_supports_json() {
        // Test that supports_json correctly identifies JSON-capable serializers
        let json_config = JsonSerializerConfig::default();
        let json_serializer = Serializer::Json(json_config.build());
        assert!(json_serializer.supports_json());

        let text_config = TextSerializerConfig::default();
        let text_serializer = Serializer::Text(text_config.build());
        assert!(!text_serializer.supports_json());
    }

    #[test]
    fn test_serializer_config_build() {
        // Test that SerializerConfig can be built successfully
        let config = SerializerConfig::Json(JsonSerializerConfig::default());
        let serializer = config.build();
        assert!(serializer.is_ok());
        assert!(matches!(serializer.unwrap(), Serializer::Json(_)));
    }

    #[test]
    fn test_serializer_config_default_framing() {
        // Test that default framing is appropriate for each serializer type
        let json_config = SerializerConfig::Json(JsonSerializerConfig::default());
        assert!(matches!(
            json_config.default_stream_framing(),
            FramingConfig::NewlineDelimited
        ));

        let native_config = SerializerConfig::Native;
        assert!(matches!(
            native_config.default_stream_framing(),
            FramingConfig::LengthDelimited(_)
        ));
    }

    // Tests for validate_structure - structural validation without I/O

    #[test]
    fn test_protobuf_validate_structure_no_io_for_nonexistent_file() {
        // This test proves that validate_structure does NOT perform filesystem I/O.
        // If it did, this would fail because the descriptor file doesn't exist.

        let config = ProtobufSerializerConfig {
            protobuf: ProtobufSerializerOptions {
                desc_file: PathBuf::from("/nonexistent/path/that/does/not/exist.desc"),
                message_type: "package.Message".to_string(),
                use_json_names: false,
            },
        };

        // validate_structure should succeed - it only checks the format, not file existence
        assert!(
            config.validate_structure().is_ok(),
            "validate_structure should not read the descriptor file"
        );

        // But build() would fail because the file doesn't exist
        assert!(
            config.build().is_err(),
            "build() should fail because the file doesn't exist"
        );
    }

    #[test]
    fn test_protobuf_validate_structure_rejects_empty_message_type() {
        let config = ProtobufSerializerConfig {
            protobuf: ProtobufSerializerOptions {
                desc_file: PathBuf::from("/some/path.desc"),
                message_type: "".to_string(),
                use_json_names: false,
            },
        };

        let err = config.validate_structure().unwrap_err();
        assert!(
            err.to_string().contains("message_type"),
            "error should mention message_type"
        );
    }

    #[test]
    fn test_protobuf_validate_structure_rejects_unqualified_message_type() {
        let config = ProtobufSerializerConfig {
            protobuf: ProtobufSerializerOptions {
                desc_file: PathBuf::from("/some/path.desc"),
                message_type: "MessageWithoutPackage".to_string(), // missing package prefix
                use_json_names: false,
            },
        };

        let err = config.validate_structure().unwrap_err();
        assert!(
            err.to_string().contains("fully qualified"),
            "error should mention fully qualified: {:?}",
            err
        );
    }

    #[test]
    fn test_protobuf_validate_structure_rejects_empty_desc_file() {
        let config = ProtobufSerializerConfig {
            protobuf: ProtobufSerializerOptions {
                desc_file: PathBuf::new(), // empty path
                message_type: "package.Message".to_string(),
                use_json_names: false,
            },
        };

        let err = config.validate_structure().unwrap_err();
        assert!(
            err.to_string().contains("desc_file"),
            "error should mention desc_file"
        );
    }

    #[test]
    fn test_encoding_config_validate_structure_for_protobuf() {
        // Create a SerializerConfig with Protobuf serializer and nonexistent file
        let protobuf_config = ProtobufSerializerConfig {
            protobuf: ProtobufSerializerOptions {
                desc_file: PathBuf::from("/nonexistent/path.desc"),
                message_type: "package.Message".to_string(),
                use_json_names: false,
            },
        };

        let serializer_config = SerializerConfig::Protobuf(protobuf_config);

        // validate_structure should succeed - no I/O is performed
        assert!(
            serializer_config.validate_structure().is_ok(),
            "SerializerConfig::validate_structure should not perform I/O"
        );
    }
}
