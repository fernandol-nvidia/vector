use crate::{
    http::Auth,
    sinks::{
        doris::{
            client::ThreadSafeDorisSinkClient,
            config::{DorisConfig, ValidatedDoris, ValidatedDorisEndpoint},
            request_builder::DorisRequestBuilder,
        },
        prelude::Compression,
    },
    tls::TlsSettings,
};
use http::Uri;
use vector_lib::codecs::{Encoder, SinkType, encoding::Framer};

#[derive(Debug, Clone)]
pub struct DorisCommon {
    pub base_url: Uri,
    pub auth: Option<Auth>,
    pub request_builder: DorisRequestBuilder,
    pub tls_settings: TlsSettings,
}

impl DorisCommon {
    pub fn parse_config(
        config: &DorisConfig,
        endpoint: &ValidatedDorisEndpoint,
    ) -> crate::Result<Self> {
        let auth = endpoint.auth().cloned();
        let base_url = endpoint.base_url().clone();
        let tls_settings = TlsSettings::from_options(config.tls.as_ref())?;

        // Build encoder from the encoding configuration
        let transformer = config.encoding.transformer();
        let (framer, serializer) = config.encoding.build(SinkType::StreamBased)?;
        let encoder = Encoder::<Framer>::new(framer, serializer);

        let request_builder = DorisRequestBuilder {
            compression: Compression::None,
            encoder: (transformer, encoder),
        };

        Ok(Self {
            base_url,
            auth,
            request_builder,
            tls_settings,
        })
    }

    pub fn parse_many(
        config: &DorisConfig,
        validated: &ValidatedDoris,
    ) -> crate::Result<Vec<Self>> {
        let mut commons = Vec::new();
        for endpoint in validated.endpoints() {
            commons.push(Self::parse_config(config, endpoint)?);
        }
        Ok(commons)
    }

    pub async fn healthcheck(&self, client: ThreadSafeDorisSinkClient) -> crate::Result<()> {
        client.healthcheck_fenode(&self.base_url).await
    }
}
