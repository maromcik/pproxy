use async_trait::async_trait;
use log::{debug, error, warn};
use pingora::listeners::TlsAccept;
use pingora::protocols::tls::TlsRef;
use pingora::tls::{self, ssl};
use pingora::utils::tls::CertKey;
use std::collections::HashMap;

use crate::error::AppError;
use crate::proxy::upstream::ServersWithLoadBalancers;

#[derive(Debug, Clone)]
pub struct TlsSelector(HashMap<String, CertKey>);

impl TlsSelector {
    pub fn new(servers: &ServersWithLoadBalancers) -> Result<Self, AppError> {
        let mut res = HashMap::new();
        for (sni, server) in &servers.0 {
            if let (Some(cert), Some(key)) = (
                server.server_config.cert_path.as_ref(),
                server.server_config.key_path.as_ref(),
            ) {
                let sni = sni.split(':').next().unwrap_or(sni).to_string();
                let cert_bytes = std::fs::read(cert)
                    .map_err(|e| AppError::IOError(format!("Certificate {cert} not found: {e}")))?;
                let certs = tls::x509::X509::stack_from_pem(&cert_bytes)?;

                let key_bytes = std::fs::read(key)?;
                let key = tls::pkey::PKey::private_key_from_pem(&key_bytes)
                    .map_err(|e| AppError::IOError(format!("Key {key} not found: {e}")))?;
                let pair = CertKey::new(certs, key);
                res.insert(sni.clone(), pair);
            }
        }

        Ok(Self(res))
    }
}

#[async_trait]
impl TlsAccept for TlsSelector {
    async fn certificate_callback(&self, ssl: &mut TlsRef) -> () {
        let Some(sni_provided) = ssl.servername(ssl::NameType::HOST_NAME) else {
            warn!("TLS: No SNI provided");
            return;
        };
        debug!("TLS: SNI provided: {}", sni_provided);
        let Some(certs) = self.0.get(sni_provided) else {
            warn!("TLS: No certificate found for SNI: {}", sni_provided);
            return;
        };

        if let Err(e) = tls::ext::ssl_use_certificate(ssl, certs.leaf()) {
            error!("TLS: Could not add leaf cert: {}", e);
        }

        for (i, cert) in certs.intermediates().iter().enumerate() {
            if let Err(e) = tls::ext::ssl_add_chain_cert(ssl, cert) {
                error!("TLS: Could not add intermediate cert {}: {}", i, e);
            }
        }

        if let Err(e) = tls::ext::ssl_use_private_key(ssl, certs.key()) {
            error!("TLS: Could not set private key: {}", e);
        }
    }
}
