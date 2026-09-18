use log::{debug, warn};
use pingora::tls::sign::CertifiedKey;
use pingora::tls::{
    ClientHello, CryptoProvider, ResolvesServerCert, install_default_crypto_provider,
    load_certs_and_key_files,
};
use std::collections::HashMap;
use std::sync::Arc;

use crate::error::AppError;
use crate::proxy::upstream::ServersWithLoadBalancers;

#[derive(Debug)]
pub struct TlsSelector(HashMap<String, Arc<CertifiedKey>>);

impl TlsSelector {
    pub fn new(servers: &ServersWithLoadBalancers) -> Result<Self, AppError> {
        install_default_crypto_provider();
        let provider = CryptoProvider::get_default().ok_or_else(|| {
            AppError::TlsError("No default rustls crypto provider installed".to_string())
        })?;

        let mut res = HashMap::new();
        for (sni, server) in &servers.0 {
            if let (Some(cert), Some(key)) = (
                server.server_config.cert_path.as_ref(),
                server.server_config.key_path.as_ref(),
            ) {
                let sni = sni.split(':').next().unwrap_or(sni).to_string();
                let Some((certs, key_der)) = load_certs_and_key_files(cert, key)? else {
                    return Err(AppError::TlsError(format!(
                        "Certificate {cert} or key {key} not found or invalid"
                    )));
                };
                let signing_key = provider
                    .key_provider
                    .load_private_key(key_der)
                    .map_err(|e| AppError::TlsError(format!("Key {key} is not supported: {e}")))?;
                res.insert(sni, Arc::new(CertifiedKey::new(certs, signing_key)));
            }
        }

        Ok(Self(res))
    }
}

impl ResolvesServerCert for TlsSelector {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let Some(sni_provided) = client_hello.server_name() else {
            warn!("TLS: No SNI provided");
            return None;
        };
        debug!("TLS: SNI provided: {}", sni_provided);
        let Some(certs) = self.0.get(sni_provided) else {
            warn!("TLS: No certificate found for SNI: {}", sni_provided);
            return None;
        };
        Some(certs.clone())
    }
}
