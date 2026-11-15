//! TLS for the daemon's TCP endpoints, with `rustls` on `ring`.
//!
//! The certificates and keys are read once, before the sandbox closes the
//! file system; a new certificate needs a restart. With a client CA, every
//! client has to present a certificate it signed: that authenticates the
//! ClamAV protocol, which has no place for a token, and any other.

use std::cell::RefCell;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig, ServerConnection, StreamOwned};

/// What every TLS connection is accepted with.
pub type Config = Arc<ServerConfig>;

/// Where the server's certificate chain and key, and the CA its clients'
/// certificates have to be signed by, if any, are kept. Each is PEM.
#[derive(Debug, Clone)]
pub struct Files<'a> {
    pub certificate: &'a Path,
    pub key: &'a Path,
    pub client_ca: Option<&'a Path>,
}

fn certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
    let found = CertificateDer::pem_file_iter(path)
        .and_then(|certificates| certificates.collect::<Result<Vec<_>, _>>())
        .map_err(|error| format!("{}: {error}", path.display()))?;
    if found.is_empty() {
        return Err(format!("{}: no certificate in the file", path.display()));
    }
    Ok(found)
}

/// The configuration every TLS connection is accepted with.
pub fn server_config(files: &Files<'_>) -> Result<Config, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let chain = certificates(files.certificate)?;
    let key = PrivateKeyDer::from_pem_file(files.key)
        .map_err(|error| format!("{}: {error}", files.key.display()))?;
    let builder = ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .map_err(|error| error.to_string())?;
    let builder = match files.client_ca {
        Some(path) => {
            let mut roots = RootCertStore::empty();
            for certificate in certificates(path)? {
                roots
                    .add(certificate)
                    .map_err(|error| format!("{}: {error}", path.display()))?;
            }
            let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider)
                .build()
                .map_err(|error| format!("{}: {error}", path.display()))?;
            builder.with_client_cert_verifier(verifier)
        }
        None => builder.with_no_client_auth(),
    };
    let config = builder
        .with_single_cert(chain, key)
        .map_err(|error| format!("{}: {error}", files.certificate.display()))?;
    Ok(Arc::new(config))
}

/// A TLS connection over TCP, used by one thread through shared references
/// as the plain streams are.
#[derive(Debug)]
pub struct Stream(RefCell<StreamOwned<ServerConnection, TcpStream>>);

impl Stream {
    pub fn new(config: &Config, socket: TcpStream) -> io::Result<Self> {
        let connection = ServerConnection::new(Arc::clone(config)).map_err(io::Error::other)?;
        Ok(Self(RefCell::new(StreamOwned::new(connection, socket))))
    }

    pub fn socket(&self) -> std::cell::Ref<'_, TcpStream> {
        std::cell::Ref::map(self.0.borrow(), |stream| &stream.sock)
    }

    /// Finish the handshake within `limit`, however slowly the client sends
    /// it: each read and write is bounded by the socket's timeouts, and the
    /// whole by `limit`.
    pub fn handshake(&self, limit: Duration) -> io::Result<()> {
        let started = Instant::now();
        let mut stream = self.0.borrow_mut();
        let StreamOwned { conn, sock } = &mut *stream;
        while conn.is_handshaking() {
            if started.elapsed() > limit {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "the TLS handshake took too long",
                ));
            }
            if conn.wants_write() {
                conn.write_tls(sock)?;
                continue;
            }
            if conn.read_tls(sock)? == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            if let Err(error) = conn.process_new_packets() {
                // Tell the client why, if it is still listening.
                let _ = conn.write_tls(sock);
                return Err(io::Error::new(io::ErrorKind::InvalidData, error));
            }
        }
        while conn.wants_write() {
            conn.write_tls(sock)?;
        }
        Ok(())
    }

    /// Say that nothing more is coming, so that the client can tell the end
    /// of the replies from a cut connection.
    pub fn close(&self) {
        let mut stream = self.0.borrow_mut();
        stream.conn.send_close_notify();
        let StreamOwned { conn, sock } = &mut *stream;
        while conn.wants_write() {
            if conn.write_tls(sock).is_err() {
                return;
            }
        }
    }
}

impl Read for &Stream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match self.0.borrow_mut().read(buffer) {
            // A client that hangs up without `close_notify` has still sent
            // whole requests; what it left unfinished fails to parse.
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(0),
            outcome => outcome,
        }
    }
}

impl Write for &Stream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.0.borrow_mut().write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.borrow_mut().flush()
    }
}
