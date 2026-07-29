use std::time::Duration;

use rand::Rng;
use rumqttc::{MqttOptions, QoS, TlsConfiguration, Transport};
use snafu::ResultExt;
use vector_lib::codecs::JsonSerializerConfig;

use crate::{
    codecs::EncodingConfig,
    common::mqtt::{
        ConfigurationError, ConfigurationSnafu, MqttCommonConfig, MqttConnector, MqttError,
        TlsSnafu,
    },
    config::{AcknowledgementsConfig, Input, SinkConfig, SinkContext},
    sinks::{Healthcheck, VectorSink, mqtt::sink::MqttSink, prelude::*},
    template::{ConfinementConfig, Template},
    tls::MaybeTlsSettings,
};

/// Configuration for the `mqtt` sink
#[configurable_component(sink("mqtt"))]
#[derive(Clone, Debug)]
pub struct MqttSinkConfig {
    #[serde(flatten)]
    pub common: MqttCommonConfig,

    /// If set to true, the MQTT session is cleaned on login.
    #[serde(default = "default_clean_session")]
    pub clean_session: bool,

    /// MQTT publish topic (templates allowed)
    pub topic: Template,

    /// Whether the messages should be retained by the server
    #[serde(default = "default_retain")]
    pub retain: bool,

    #[configurable(derived)]
    pub encoding: EncodingConfig,

    #[configurable(derived)]
    #[serde(
        default,
        deserialize_with = "crate::serde::bool_or_struct",
        skip_serializing_if = "crate::serde::is_default"
    )]
    pub acknowledgements: AcknowledgementsConfig,

    #[configurable(derived)]
    #[serde(default = "default_qos")]
    pub quality_of_service: MqttQoS,

    #[configurable(derived)]
    #[serde(flatten)]
    pub confinement: ConfinementConfig,
}

/// Supported Quality of Service types for MQTT.
#[configurable_component]
#[derive(Clone, Copy, Debug, Default)]
#[serde(rename_all = "lowercase")]
#[allow(clippy::enum_variant_names)]
pub enum MqttQoS {
    /// AtLeastOnce.
    #[default]
    AtLeastOnce,

    /// AtMostOnce.
    AtMostOnce,

    /// ExactlyOnce.
    ExactlyOnce,
}

impl From<MqttQoS> for QoS {
    fn from(value: MqttQoS) -> Self {
        match value {
            MqttQoS::AtLeastOnce => QoS::AtLeastOnce,
            MqttQoS::AtMostOnce => QoS::AtMostOnce,
            MqttQoS::ExactlyOnce => QoS::ExactlyOnce,
        }
    }
}

const fn default_clean_session() -> bool {
    false
}

const fn default_qos() -> MqttQoS {
    MqttQoS::AtLeastOnce
}

const fn default_retain() -> bool {
    false
}

impl Default for MqttSinkConfig {
    fn default() -> Self {
        Self {
            common: MqttCommonConfig::default(),
            clean_session: default_clean_session(),

            topic: Template::try_from("vector").expect("Cannot parse as a template"),
            retain: default_retain(),
            encoding: JsonSerializerConfig::default().into(),
            acknowledgements: AcknowledgementsConfig::default(),
            quality_of_service: MqttQoS::default(),
            confinement: ConfinementConfig::default(),
        }
    }
}

impl_generate_config_from_default!(MqttSinkConfig);

#[async_trait::async_trait]
#[typetag::serde(name = "mqtt")]
impl SinkConfig for MqttSinkConfig {
    async fn build(&self, _cx: SinkContext) -> crate::Result<(VectorSink, Healthcheck)> {
        let topic = self
            .topic
            .clone()
            .confine(&self.confinement, Self::NAME, "topic")?;
        let connector = self.build_connector()?;
        let sink = MqttSink::new(self, topic, connector.clone())?;
        Ok((
            VectorSink::from_event_streamsink(sink),
            Box::pin(async move { connector.healthcheck().await }),
        ))
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

    fn validate_structure(&self) -> std::result::Result<(), Vec<String>> {
        let mut errors = Vec::new();

        // Check for empty client_id
        if let Some(client_id) = &self.common.client_id
            && client_id.is_empty()
        {
            errors.push("client_id cannot be empty".to_string());
        }

        // Check for invalid credentials (only one of user/password set)
        match (&self.common.user, &self.common.password) {
            (Some(_), None) | (None, Some(_)) => {
                errors.push("both user and password must be set together".to_string());
            }
            _ => {}
        }

        if let Err(e) = self
            .topic
            .clone()
            .confine(&self.confinement, Self::NAME, "topic")
        {
            errors.push(e.to_string());
        }

        // Validate encoding configuration
        if let Err(e) = self.encoding.build() {
            errors.push(format!("encoding: {}", e));
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

impl MqttSinkConfig {
    fn build_connector(&self) -> Result<MqttConnector, MqttError> {
        let client_id = self.common.client_id.clone().unwrap_or_else(|| {
            let hash = rand::rng()
                .sample_iter(&rand_distr::Alphanumeric)
                .take(6)
                .map(char::from)
                .collect::<String>();
            format!("vectorSink{hash}")
        });

        if client_id.is_empty() {
            return Err(ConfigurationError::EmptyClientId).context(ConfigurationSnafu);
        }
        let tls =
            MaybeTlsSettings::from_config(self.common.tls.as_ref(), false).context(TlsSnafu)?;
        let mut options = MqttOptions::new(&client_id, &self.common.host, self.common.port);
        options.set_keep_alive(Duration::from_secs(self.common.keep_alive.into()));
        options.set_max_packet_size(self.common.max_packet_size, self.common.max_packet_size);
        options.set_clean_session(self.clean_session);
        match (&self.common.user, &self.common.password) {
            (Some(user), Some(password)) => {
                options.set_credentials(user, password);
            }
            (None, None) => {}
            _ => {
                return Err(MqttError::Configuration {
                    source: ConfigurationError::InvalidCredentials,
                });
            }
        }
        if let Some(tls) = tls.tls() {
            let ca = tls.authorities_pem().flatten().collect();
            let client_auth = tls.identity_pem();
            // Honor the user-configured `tls.alpn_protocols` (e.g. `x-amzn-mqtt-ca`, required to
            // reach AWS IoT Core over port 443), falling back to `mqtt` when it is not set.
            let alpn = self
                .common
                .tls
                .as_ref()
                .and_then(|tls| tls.options.alpn_protocols.as_ref())
                .filter(|protocols| !protocols.is_empty())
                .map(|protocols| protocols.iter().map(|p| p.clone().into_bytes()).collect())
                .unwrap_or_else(|| vec![b"mqtt".to_vec()]);
            options.set_transport(Transport::Tls(TlsConfiguration::Simple {
                ca,
                client_auth,
                alpn: Some(alpn),
            }));
        }
        Ok(MqttConnector::new(options))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::template::{ConfinementConfig, Template};

    #[test]
    fn generate_config() {
        crate::test_util::test_generate_config::<MqttSinkConfig>();
    }

    #[test]
    fn confinement_rejects_unconfined_topic() {
        let template = Template::try_from("{{ topic }}").unwrap();
        let config = ConfinementConfig::default();
        let result = template.confine(&config, "mqtt", "topic");
        assert!(result.is_err());
    }

    #[test]
    fn confinement_opt_out_allows_unconfined_topic() {
        let template = Template::try_from("{{ topic }}").unwrap();
        let config = ConfinementConfig {
            dangerously_allow_unconfined_template_resolution: true,
        };
        let result = template.confine(&config, "mqtt", "topic");
        assert!(result.is_ok());
    }

    #[test]
    fn confinement_allows_prefixed_topic() {
        let template = Template::try_from("events-{{ env }}").unwrap();
        let config = ConfinementConfig::default();
        let result = template.confine(&config, "mqtt", "topic");
        assert!(result.is_ok());
    }

    #[test]
    fn validate_structure_rejects_empty_client_id() {
        use crate::common::mqtt::MqttCommonConfig;

        let config = MqttSinkConfig {
            common: MqttCommonConfig {
                client_id: Some("".to_string()),
                ..MqttCommonConfig::default()
            },
            ..MqttSinkConfig::default()
        };

        let errors = config.validate_structure().unwrap_err();
        assert_eq!(errors.len(), 1);
        assert!(
            errors[0].contains("client_id"),
            "unexpected error: {:?}",
            errors[0]
        );
    }

    #[test]
    fn validate_structure_rejects_user_without_password() {
        use crate::common::mqtt::MqttCommonConfig;

        let config = MqttSinkConfig {
            common: MqttCommonConfig {
                user: Some("user".to_string()),
                password: None,
                ..MqttCommonConfig::default()
            },
            ..MqttSinkConfig::default()
        };

        let errors = config.validate_structure().unwrap_err();
        assert_eq!(errors.len(), 1);
        assert!(
            errors[0].contains("user") && errors[0].contains("password"),
            "unexpected error: {:?}",
            errors[0]
        );
    }

    #[test]
    fn validate_structure_rejects_password_without_user() {
        use crate::common::mqtt::MqttCommonConfig;

        let config = MqttSinkConfig {
            common: MqttCommonConfig {
                user: None,
                password: Some("secret".to_string()),
                ..MqttCommonConfig::default()
            },
            ..MqttSinkConfig::default()
        };

        let errors = config.validate_structure().unwrap_err();
        assert_eq!(errors.len(), 1);
        assert!(
            errors[0].contains("user") && errors[0].contains("password"),
            "unexpected error: {:?}",
            errors[0]
        );
    }

    #[test]
    fn validate_structure_allows_valid_credentials() {
        use crate::common::mqtt::MqttCommonConfig;

        let config = MqttSinkConfig {
            common: MqttCommonConfig {
                user: Some("user".to_string()),
                password: Some("secret".to_string()),
                ..MqttCommonConfig::default()
            },
            ..MqttSinkConfig::default()
        };

        config.validate_structure().unwrap();
    }
}
