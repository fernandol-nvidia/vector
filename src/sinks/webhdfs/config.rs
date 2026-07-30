use opendal::{Operator, layers::LoggingLayer, services::Webhdfs};
use tower::ServiceBuilder;
use vector_lib::{
    codecs::{JsonSerializerConfig, NewlineDelimitedEncoderConfig, encoding::Framer},
    config::{AcknowledgementsConfig, DataType, Input},
    configurable::configurable_component,
    sink::VectorSink,
    stream::BatcherSettings,
};

use crate::{
    codecs::{Encoder, EncodingConfigWithFraming, SinkType},
    config::{GenerateConfig, SinkConfig, SinkContext, ValidateSink},
    sinks::{
        Healthcheck,
        opendal_common::*,
        util::{
            BatchConfig, BulkSizeBasedDefaultBatchSettings, Compression,
            partitioner::KeyPartitioner,
        },
    },
    template::{ConfinedTemplate, ConfinementConfig, Template},
};

/// Configuration for the `webhdfs` sink.
#[configurable_component(sink("webhdfs", "WebHDFS."))]
#[derive(Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct WebHdfsConfig {
    /// The root path for WebHDFS.
    ///
    /// Must be a valid directory.
    ///
    /// The final file path is in the format of `{root}/{prefix}{suffix}`.
    #[serde(default)]
    pub root: String,

    /// A prefix to apply to all keys.
    ///
    /// Prefixes are useful for partitioning objects, such as by creating a blob key that
    /// stores blobs under a particular directory. If using a prefix for this purpose, it must end
    /// in `/` to act as a directory path. A trailing `/` is **not** automatically added.
    ///
    /// The final file path is in the format of `{root}/{prefix}{suffix}`.
    #[serde(default)]
    #[configurable(metadata(docs::templateable))]
    pub prefix: String,

    /// An HDFS cluster consists of a single NameNode, a master server that manages the file system namespace and regulates access to files by clients.
    ///
    /// The endpoint is the HDFS's web restful HTTP API endpoint.
    ///
    /// For more information, see the [HDFS Architecture][hdfs_arch] documentation.
    ///
    /// [hdfs_arch]: https://hadoop.apache.org/docs/r3.3.4/hadoop-project-dist/hadoop-hdfs/HdfsDesign.html#NameNode_and_DataNodes
    #[serde(default)]
    #[configurable(metadata(docs::examples = "http://127.0.0.1:9870"))]
    pub endpoint: String,

    #[serde(flatten)]
    pub encoding: EncodingConfigWithFraming,

    #[configurable(derived)]
    #[serde(default = "Compression::gzip_default")]
    pub compression: Compression,

    #[configurable(derived)]
    #[serde(default)]
    pub batch: BatchConfig<BulkSizeBasedDefaultBatchSettings>,

    #[configurable(derived)]
    #[serde(
        default,
        deserialize_with = "crate::serde::bool_or_struct",
        skip_serializing_if = "crate::serde::is_default"
    )]
    pub acknowledgements: AcknowledgementsConfig,

    #[serde(flatten)]
    pub confinement: ConfinementConfig,
}

impl GenerateConfig for WebHdfsConfig {
    fn generate_config() -> serde_json::Value {
        serde_json::to_value(Self {
            root: "/".to_string(),
            prefix: "%F/".to_string(),
            endpoint: "http://127.0.0.1:9870".to_string(),

            encoding: (
                Some(NewlineDelimitedEncoderConfig::new()),
                JsonSerializerConfig::default(),
            )
                .into(),
            compression: Compression::gzip_default(),
            batch: BatchConfig::default(),

            acknowledgements: Default::default(),
            confinement: ConfinementConfig::default(),
        })
        .unwrap()
    }
}

/// Values derived while validating [`WebHdfsConfig`], consumed by its `build`.
///
/// The fields are private, so the only way to obtain the confined prefix template and batcher
/// settings the sink uses is [`ValidateSink::validate`].
#[derive(Debug)]
pub struct ValidatedWebHdfs {
    prefix: ConfinedTemplate,
    batcher_settings: BatcherSettings,
}

impl ValidateSink for WebHdfsConfig {
    type Validated = ValidatedWebHdfs;

    fn validate(&self) -> std::result::Result<Self::Validated, Vec<String>> {
        let mut errors = Vec::new();

        let prefix = Template::try_from(self.prefix.clone())
            .map_err(|e| format!("prefix: {e}"))
            .and_then(|tpl| {
                tpl.confine(&self.confinement, Self::NAME, "prefix")
                    .map_err(|e| e.to_string())
            })
            .inspect_err(|e| errors.push(e.clone()))
            .ok();

        let batcher_settings = self
            .batch
            .into_batcher_settings()
            .inspect_err(|e| errors.push(format!("batch: {e}")))
            .ok();

        // Validate encoding configuration (structural checks only, no I/O)
        if let Err(e) = self.encoding.validate_structure() {
            errors.push(format!("encoding: {e}"));
        }

        match (errors.is_empty(), prefix, batcher_settings) {
            (true, Some(prefix), Some(batcher_settings)) => Ok(ValidatedWebHdfs {
                prefix,
                batcher_settings,
            }),
            _ => Err(errors),
        }
    }
}

#[async_trait::async_trait]
#[typetag::serde(name = "webhdfs")]
impl SinkConfig for WebHdfsConfig {
    async fn build(&self, _cx: SinkContext) -> crate::Result<(VectorSink, Healthcheck)> {
        let ValidatedWebHdfs {
            prefix,
            batcher_settings,
        } = self.validate().map_err(|errors| errors.join("; "))?;

        let op = self.build_operator()?;

        let check_op = op.clone();
        let healthcheck = Box::pin(async move { Ok(check_op.check().await?) });

        let sink = self.build_processor_with_validated(op, prefix, batcher_settings)?;
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

    fn validate_structure(&self) -> std::result::Result<(), Vec<String>> {
        self.validate().map(|_| ())
    }
}

impl WebHdfsConfig {
    pub fn build_operator(&self) -> crate::Result<Operator> {
        // Build OpenDal Operator
        let mut builder = Webhdfs::default();
        // Prefix logic will be handled by key_partitioner.
        builder = builder.root(&self.root);
        builder = builder.endpoint(&self.endpoint);

        let op = Operator::new(builder)?
            .layer(LoggingLayer::default())
            .finish();
        Ok(op)
    }

    pub fn build_processor(&self, op: Operator) -> crate::Result<VectorSink> {
        let ValidatedWebHdfs {
            prefix,
            batcher_settings,
        } = self.validate().map_err(|errors| errors.join("; "))?;

        self.build_processor_with_validated(op, prefix, batcher_settings)
    }

    fn build_processor_with_validated(
        &self,
        op: Operator,
        prefix: ConfinedTemplate,
        batcher_settings: BatcherSettings,
    ) -> crate::Result<VectorSink> {
        let transformer = self.encoding.transformer();
        let (framer, serializer) = self.encoding.build(SinkType::MessageBased)?;
        let encoder = Encoder::<Framer>::new(framer, serializer);

        let request_builder = OpenDalRequestBuilder {
            encoder: (transformer, encoder),
            compression: self.compression,
        };

        // TODO: we can add tower middleware here.
        let svc = ServiceBuilder::new().service(OpenDalService::new(op));

        let sink = OpenDalSink::new(
            svc,
            request_builder,
            KeyPartitioner::new(prefix, None),
            batcher_settings,
        );

        Ok(VectorSink::from_event_streamsink(sink))
    }

    pub fn key_partitioner(&self) -> crate::Result<KeyPartitioner> {
        let ValidatedWebHdfs { prefix, .. } =
            self.validate().map_err(|errors| errors.join("; "))?;
        Ok(KeyPartitioner::new(prefix, None))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_config() {
        crate::test_util::test_generate_config::<WebHdfsConfig>();
    }

    fn base_config() -> WebHdfsConfig {
        WebHdfsConfig {
            root: "/tmp/test/".into(),
            prefix: String::new(),
            endpoint: "http://127.0.0.1:9870".into(),
            encoding: (
                None::<vector_lib::codecs::encoding::FramingConfig>,
                vector_lib::codecs::TextSerializerConfig::default(),
            )
                .into(),
            compression: crate::sinks::util::Compression::None,
            batch: Default::default(),
            acknowledgements: Default::default(),
            confinement: ConfinementConfig::default(),
        }
    }

    #[test]
    fn confinement_rejects_unconfined_prefix() {
        let config = WebHdfsConfig {
            prefix: "{{ tenant }}".into(),
            ..base_config()
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
    fn confinement_opt_out_allows_unconfined_prefix() {
        let config = WebHdfsConfig {
            prefix: "{{ tenant }}".into(),
            confinement: ConfinementConfig {
                dangerously_allow_unconfined_template_resolution: true,
            },
            ..base_config()
        };
        assert!(config.key_partitioner().is_ok());
    }

    #[test]
    fn validate_yields_confined_prefix() {
        use crate::event::Event;
        use vector_lib::event::LogEvent;
        use vector_lib::partition::Partitioner;
        use vrl::event_path;

        let config = WebHdfsConfig {
            prefix: "safe/{{ tenant }}/".into(),
            ..base_config()
        };
        let ValidatedWebHdfs {
            prefix,
            batcher_settings: _,
        } = config.validate().unwrap();
        let partitioner = KeyPartitioner::new(prefix, None);
        let mut event = Event::Log(LogEvent::from("x"));
        event.as_mut_log().insert(event_path!("tenant"), "acme");

        assert_eq!(partitioner.partition(&event).as_deref(), Some("safe/acme/"));
    }

    #[test]
    fn confinement_blocks_dotdot_escape_at_render() {
        use crate::event::Event;
        use vector_lib::event::LogEvent;
        use vector_lib::partition::Partitioner;
        use vrl::event_path;

        let config = WebHdfsConfig {
            prefix: "safe/{{ tenant }}/".into(),
            ..base_config()
        };
        let partitioner = config.key_partitioner().unwrap();
        let mut event = Event::Log(LogEvent::from("x"));
        event
            .as_mut_log()
            .insert(event_path!("tenant"), "../../escape");
        assert!(partitioner.partition(&event).is_none());
    }
}
