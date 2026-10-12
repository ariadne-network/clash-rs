use crate::{
    config::internal::proxy::OutboundHttp,
    proxy::{
        HandlerCommonOptions,
        http::outbound::{Handler, HandlerOptions},
        transport::{TlsClient, TransportLayer},
    },
};

impl TryFrom<OutboundHttp> for Handler {
    type Error = crate::Error;

    fn try_from(value: OutboundHttp) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&OutboundHttp> for Handler {
    type Error = crate::Error;

    fn try_from(s: &OutboundHttp) -> Result<Self, Self::Error> {
        let tls_client = if s.tls {
            Some(TransportLayer::Tls(TlsClient::new(
                s.skip_cert_verify,
                s.sni.clone().unwrap_or(s.common_opts.server.to_owned()),
                None,
                None,
                None,
                None,
            )?))
        } else {
            None
        };
        Ok(Handler::new(HandlerOptions {
            name: s.common_opts.name.to_owned(),
            common_opts: HandlerCommonOptions { connector: s.common_opts.connect_via.clone(), ..Default::default() },
            server: s.common_opts.server.to_owned(),
            port: s.common_opts.port,
            user: s.username.clone(),
            password: s.password.clone(),
            tls_client,
        }))
    }
}
