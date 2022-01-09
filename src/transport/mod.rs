use crate::config::TransportConfig;
use anyhow::Result;
use async_trait::async_trait;
use std::fmt::Debug;
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::ToSocketAddrs;

// Specify a transport layer, like TCP, TLS
#[async_trait]
pub trait Transport: Debug + Send + Sync {
    type Acceptor: Send + Sync;
    type Stream: 'static + AsyncRead + AsyncWrite + Unpin + Send + Sync + Debug;

    async fn new(config: &TransportConfig) -> Result<Self>
    where
        Self: Sized;
    async fn bind<T: ToSocketAddrs + Send + Sync>(&self, addr: T) -> Result<Self::Acceptor>;
    async fn accept(&self, a: &Self::Acceptor) -> Result<(Self::Stream, SocketAddr)>;
    async fn connect(&self, addr: &str) -> Result<Self::Stream>;
}

mod tcp;
pub use tcp::TcpTransport;
#[cfg(feature = "tls")]
mod tls;
#[cfg(feature = "tls")]
pub use tls::TlsTransport;

#[cfg(feature = "noise")]
mod noise;
#[cfg(feature = "noise")]
pub use noise::NoiseTransport;

#[cfg(feature = "quic")]
mod quic;
#[cfg(feature = "quic")]
pub use quic::QuicTransport;
