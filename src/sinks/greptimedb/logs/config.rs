use std::collections::HashMap;

use vector_lib::{
    codecs::{JsonSerializerConfig, NewlineDelimitedEncoderConfig, encoding::Framer},
    configurable::configurable_component,
    sensitive_string::SensitiveString,
};

use crate::{
    http::{Auth, HttpClient},
    sinks::{
        greptimedb::{
            GreptimeDBDefaultBatchSettings, default_dbname_template, default_pipeline_template,
            logs::{
                http_request_builder::{
                    GreptimeDBHttpRetryLogic, GreptimeDBLogsHttpRequestBuilder, PartitionKey,
                    http_healthcheck,
                },
                sink::{GreptimeDBLogsHttpSink, LogsSinkSetting},
            },
        },
        prelude::*,
        util::http::HttpService,
    },
    template::ConfinementConfig,
};

fn extra_params_examples() -> HashMap<String, String> {
    HashMap::<_, _>::from_iter([("source".to_owned(), "vector".to_owned())])
}

/// Configuration for the `greptimedb_logs` sink.
#[configurable_component(sink("greptimedb_logs", "Ingest logs data into GreptimeDB."))]
#[derive(Clone, Debug, Default, Derivative)]
#[serde(deny_unknown_fields)]
pub struct GreptimeDBLogsConfig {
    /// The endpoint of the GreptimeDB server.
    #[serde(alias = "host")]
    #[configurable(metadata(docs::examples = "http://localhost:4000"))]
    pub endpoint: String,

    /// The table that data is inserted into.
    #[configurable(metadata(docs::examples = "mytable"))]
    pub table: Template,

    /// The [GreptimeDB database][database] name to connect.
    ///
    /// Default to `public`, the default database of GreptimeDB.
    ///
    /// Database can be created via `create database` statement on
    /// GreptimeDB. If you are using GreptimeCloud, use `dbname` from the
    /// connection information of your instance.
    ///
    /// [database]: https://docs.greptime.com/user-guide/concepts/key-concepts#database
    #[configurable(metadata(docs::examples = "public"))]
    #[derivative(Default(value = "default_dbname_template()"))]
    #[serde(default = "default_dbname_template")]
    pub dbname: Template,

    /// Pipeline name to be used for the logs.
    ///
    /// Default to `greptime_identity`, use the original log structure
    #[configurable(metadata(docs::examples = "pipeline_name"))]
    #[derivative(Default(value = "default_pipeline_template()"))]
    #[serde(default = "default_pipeline_template")]
    pub pipeline_name: Template,

    /// Pipeline version to be used for the logs.
    #[configurable(metadata(docs::examples = "2024-06-07 06:46:23.858293"))]
    pub pipeline_version: Option<Template>,

    /// The username for your GreptimeDB instance.
    ///
    /// This is required if your instance has authentication enabled.
    #[configurable(metadata(docs::examples = "username"))]
    #[serde(default)]
    pub username: Option<String>,
    /// The password for your GreptimeDB instance.
    ///
    /// This is required if your instance has authentication enabled.
    #[configurable(metadata(docs::examples = "password"))]
    #[serde(default)]
    pub password: Option<SensitiveString>,
    /// Set http compression encoding for the request
    /// Default to none, `gzip` or `zstd` is supported.
    #[configurable(derived)]
    #[serde(default = "Compression::gzip_default")]
    pub compression: Compression,

    #[configurable(derived)]
    #[serde(default, skip_serializing_if = "crate::serde::is_default")]
    pub encoding: Transformer,

    /// Custom parameters to add to the query string for each HTTP request sent to GreptimeDB.
    #[serde(default)]
    #[configurable(metadata(docs::advanced))]
    #[configurable(metadata(docs::additional_props_description = "A query string parameter."))]
    #[configurable(metadata(docs::examples = "extra_params_examples()"))]
    pub extra_params: Option<HashMap<String, String>>,

    /// Custom headers to add to the HTTP request sent to GreptimeDB.
    /// Note that these headers will override the existing headers.
    #[serde(default)]
    #[configurable(metadata(docs::advanced))]
    #[configurable(metadata(
        docs::additional_props_description = "Extra header key-value pairs."
    ))]
    pub extra_headers: Option<HashMap<String, String>>,

    #[configurable(derived)]
    #[serde(default)]
    pub(crate) batch: BatchConfig<GreptimeDBDefaultBatchSettings>,

    #[configurable(derived)]
    #[serde(default)]
    pub request: TowerRequestConfig,

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
    #[serde(flatten)]
    pub confinement: ConfinementConfig,
}

impl_generate_config_from_default!(GreptimeDBLogsConfig);

/// Values derived while validating [`GreptimeDBLogsConfig`], consumed by its `build`.
///
/// The fields are private, so the only way to obtain the confined templates and batcher settings
/// the sink uses is [`ValidateSink::validate`].
#[derive(Debug)]
pub struct ValidatedGreptimeDBLogs {
    table: ConfinedTemplate,
    dbname: ConfinedTemplate,
    pipeline_name: ConfinedTemplate,
    pipeline_version: Option<ConfinedTemplate>,
    batcher_settings: BatcherSettings,
}

impl ValidateSink for GreptimeDBLogsConfig {
    type Validated = ValidatedGreptimeDBLogs;

    fn validate(&self) -> std::result::Result<Self::Validated, Vec<String>> {
        let mut errors = Vec::new();

        if let Err(e) = url::Url::parse(&self.endpoint) {
            errors.push(format!("endpoint: invalid URL: {e}"));
        }

        let table = self
            .table
            .clone()
            .confine(&self.confinement, Self::NAME, "table")
            .inspect_err(|e| errors.push(e.to_string()))
            .ok();

        let dbname = self
            .dbname
            .clone()
            .confine(&self.confinement, Self::NAME, "dbname")
            .inspect_err(|e| errors.push(e.to_string()))
            .ok();

        let pipeline_name = self
            .pipeline_name
            .clone()
            .confine(&self.confinement, Self::NAME, "pipeline_name")
            .inspect_err(|e| errors.push(e.to_string()))
            .ok();

        let pipeline_version = self
            .pipeline_version
            .clone()
            .map(|t| t.confine(&self.confinement, Self::NAME, "pipeline_version"))
            .transpose()
            .inspect_err(|e| errors.push(e.to_string()))
            .ok();

        let batcher_settings = self
            .batch
            .into_batcher_settings()
            .inspect_err(|e| errors.push(format!("batch: {e}")))
            .ok();

        if let Some(headers) = &self.extra_headers {
            use http::header::{HeaderName, HeaderValue};
            for (name, value) in headers {
                if let Err(e) = HeaderName::from_bytes(name.as_bytes()) {
                    errors.push(format!("extra_headers.{name}: invalid header name: {e}"));
                }
                if let Err(e) = HeaderValue::from_str(value) {
                    errors.push(format!("extra_headers.{name}: invalid header value: {e}"));
                }
            }
        }

        match (
            errors.is_empty(),
            table,
            dbname,
            pipeline_name,
            pipeline_version,
            batcher_settings,
        ) {
            (
                true,
                Some(table),
                Some(dbname),
                Some(pipeline_name),
                Some(pipeline_version),
                Some(batcher_settings),
            ) => Ok(ValidatedGreptimeDBLogs {
                table,
                dbname,
                pipeline_name,
                pipeline_version,
                batcher_settings,
            }),
            _ => Err(errors),
        }
    }
}

#[async_trait::async_trait]
#[typetag::serde(name = "greptimedb_logs")]
impl SinkConfig for GreptimeDBLogsConfig {
    fn validate_structure(&self) -> std::result::Result<(), Vec<String>> {
        self.validate().map(|_| ())
    }

    async fn build(&self, cx: SinkContext) -> crate::Result<(VectorSink, Healthcheck)> {
        let ValidatedGreptimeDBLogs {
            table,
            dbname,
            pipeline_name,
            pipeline_version,
            batcher_settings,
        } = self.validate().map_err(|errors| errors.join("; "))?;

        let tls_settings = TlsSettings::from_options(self.tls.as_ref())?;
        let client = HttpClient::new(tls_settings, &cx.proxy)?;

        let auth = match (self.username.clone(), self.password.clone()) {
            (Some(username), Some(password)) => Some(Auth::Basic {
                user: username,
                password,
            }),
            _ => None,
        };
        let request_builder = GreptimeDBLogsHttpRequestBuilder {
            endpoint: self.endpoint.clone(),
            auth: auth.clone(),
            encoder: (
                self.encoding.clone(),
                Encoder::<Framer>::new(
                    NewlineDelimitedEncoderConfig.build().into(),
                    JsonSerializerConfig::default().build().into(),
                ),
            ),
            compression: self.compression,
            extra_params: self.extra_params.clone(),
            extra_headers: self.extra_headers.clone(),
        };

        let service: HttpService<GreptimeDBLogsHttpRequestBuilder, PartitionKey> =
            HttpService::new(client.clone(), request_builder.clone());

        let request_limits = self.request.into_settings();

        let service = ServiceBuilder::new()
            .settings(request_limits, GreptimeDBHttpRetryLogic::default())
            .service(service);

        let logs_sink_setting = LogsSinkSetting {
            dbname,
            table,
            pipeline_name,
            pipeline_version,
        };

        let sink = GreptimeDBLogsHttpSink::new(
            batcher_settings,
            service,
            request_builder,
            logs_sink_setting,
        );

        let healthcheck = Box::pin(http_healthcheck(
            client,
            self.endpoint.clone(),
            auth.clone(),
        ));
        Ok((VectorSink::from_event_streamsink(sink), healthcheck))
    }

    fn confinement_config(&self) -> Option<&crate::template::ConfinementConfig> {
        Some(&self.confinement)
    }

    fn input(&self) -> Input {
        Input::log()
    }

    fn acknowledgements(&self) -> &AcknowledgementsConfig {
        &self.acknowledgements
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::template::{ConfinementConfig, Template};
    use vrl::event_path;

    #[test]
    fn confinement_rejects_unconfined_table() {
        let template = Template::try_from("{{ table }}").unwrap();
        let config = ConfinementConfig::default();
        let result = template.confine(&config, "greptimedb_logs", "table");
        assert!(result.is_err());
    }

    #[test]
    fn confinement_opt_out_allows_unconfined_table() {
        let template = Template::try_from("{{ table }}").unwrap();
        let config = ConfinementConfig {
            dangerously_allow_unconfined_template_resolution: true,
        };
        let result = template.confine(&config, "greptimedb_logs", "table");
        assert!(result.is_ok());
    }

    #[test]
    fn confinement_allows_prefixed_table() {
        let template = Template::try_from("events-{{ env }}").unwrap();
        let config = ConfinementConfig::default();
        let result = template.confine(&config, "greptimedb_logs", "table");
        assert!(result.is_ok());
    }

    #[test]
    fn validate_structure_rejects_invalid_endpoint() {
        use crate::config::SinkConfig;

        let config = GreptimeDBLogsConfig {
            endpoint: "not a valid url".to_string(),
            ..GreptimeDBLogsConfig::default()
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
    fn validate_structure_rejects_endpoint_missing_scheme() {
        use crate::config::SinkConfig;

        let config = GreptimeDBLogsConfig {
            endpoint: "http://".to_string(),
            ..GreptimeDBLogsConfig::default()
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
    fn validate_structure_allows_valid_endpoint() {
        use crate::config::SinkConfig;

        let config = GreptimeDBLogsConfig {
            endpoint: "http://localhost:4000".to_string(),
            ..GreptimeDBLogsConfig::default()
        };

        config.validate_structure().unwrap();
    }

    #[test]
    fn validate_yields_confined_templates_and_batcher_settings() {
        let config = GreptimeDBLogsConfig {
            endpoint: "http://localhost:4000".to_string(),
            table: Template::try_from("events-{{ env }}").unwrap(),
            dbname: Template::try_from("db-{{ env }}").unwrap(),
            pipeline_name: Template::try_from("pipeline-{{ env }}").unwrap(),
            pipeline_version: Some(Template::try_from("version-{{ env }}").unwrap()),
            ..GreptimeDBLogsConfig::default()
        };

        let validated = config.validate().expect("config is valid");

        let mut event = LogEvent::from_str_legacy("message");
        event.insert(event_path!("env"), "prod");
        let event = Event::from(event);

        assert_eq!(
            validated.table.render_string(&event).unwrap(),
            "events-prod"
        );
        assert_eq!(validated.dbname.render_string(&event).unwrap(), "db-prod");
        assert_eq!(
            validated.pipeline_name.render_string(&event).unwrap(),
            "pipeline-prod"
        );
        assert_eq!(
            validated
                .pipeline_version
                .as_ref()
                .unwrap()
                .render_string(&event)
                .unwrap(),
            "version-prod"
        );
        assert_eq!(validated.batcher_settings.item_limit, 20);
    }

    #[test]
    fn validate_structure_rejects_invalid_header_name() {
        use crate::config::SinkConfig;
        use std::collections::HashMap;

        let config = GreptimeDBLogsConfig {
            endpoint: "http://localhost:4000".to_string(),
            extra_headers: Some(HashMap::from_iter([(
                "Invalid Header Name".to_string(),
                "value".to_string(),
            )])),
            ..GreptimeDBLogsConfig::default()
        };

        let errors = config.validate_structure().unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| e.contains("extra_headers") && e.contains("invalid header name")),
            "unexpected errors: {:?}",
            errors
        );
    }

    #[test]
    fn validate_structure_rejects_invalid_header_value() {
        use crate::config::SinkConfig;
        use std::collections::HashMap;

        let config = GreptimeDBLogsConfig {
            endpoint: "http://localhost:4000".to_string(),
            extra_headers: Some(HashMap::from_iter([(
                "X-Test".to_string(),
                "bad\nvalue".to_string(),
            )])),
            ..GreptimeDBLogsConfig::default()
        };

        let errors = config.validate_structure().unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| e.contains("extra_headers") && e.contains("invalid header value")),
            "unexpected errors: {:?}",
            errors
        );
    }
}
