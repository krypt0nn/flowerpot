// SPDX-License-Identifier: GPL-3.0-or-later
//
// libflowerpot
// Copyright (C) 2025  Nikita Podvirnyi <krypt0nn@vk.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

use std::io::{Read, Write};
use std::net::{SocketAddr, ToSocketAddrs};

/// Abstract client/listener transport.
#[allow(async_fn_in_trait)]
pub trait Transport {
    type Stream: Stream;
    type Error: std::error::Error;

    /// Listen to incoming stream connections.
    async fn listen(&self) -> Result<Self::Stream, Self::Error>;

    /// Try to make a stream connection.
    async fn connect(
        &self,
        address: impl ToSocketAddrs
    ) -> Result<Self::Stream, Self::Error>;
}

/// Abstract data transportation stream.
#[allow(async_fn_in_trait)]
pub trait Stream {
    /// Get socket address of the local endpoint.
    fn local_address(&self) -> &SocketAddr;

    /// Get socket address of remote endpoint.
    fn remote_address(&self) -> &SocketAddr;

    /// Read content from the network, write it to the `buf` writer. Return
    /// amount of read bytes.
    async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize>;

    /// Read content from the network with exact length in bytes, write it
    /// to the `buf` writer.
    async fn read_exact(&mut self, buf: &mut [u8]) -> std::io::Result<()>;

    /// Send content of the `buf` reader.
    async fn write(&mut self, buf: &[u8]) -> std::io::Result<()>;

    /// Send all the buffered data if there's any.
    async fn flush(&mut self) -> std::io::Result<()>;
}

#[derive(Debug, thiserror::Error)]
pub enum TcpSocketError {
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error("tcp socket must be bound to some local address before listening to incoming connections")]
    SocketNotBound
}

#[derive(Default, Debug)]
pub struct TcpSocket(Option<std::net::TcpListener>);

impl TcpSocket {
    pub fn bind(address: impl ToSocketAddrs) -> std::io::Result<Self> {
        Ok(Self(Some(std::net::TcpListener::bind(address)?)))
    }
}

impl Transport for TcpSocket {
    type Error = TcpSocketError;
    type Stream = TcpStream;

    async fn listen(&self) -> Result<Self::Stream, Self::Error> {
        let Some(listener) = &self.0 else {
            return Err(TcpSocketError::SocketNotBound);
        };

        let (stream, address) = listener.accept()?;

        let local_address = stream.local_addr()?;
        let remote_address = address;

        #[cfg(feature = "tracing")]
        tracing::trace!(
            ?local_address,
            ?remote_address,
            "tcp connection accepted"
        );

        Ok(TcpStream {
            local_address,
            remote_address,
            stream
        })
    }

    async fn connect(
        &self,
        address: impl ToSocketAddrs
    ) -> Result<Self::Stream, Self::Error> {
        let stream = std::net::TcpStream::connect(address)?;

        let local_address = stream.local_addr()?;
        let remote_address = stream.peer_addr()?;

        #[cfg(feature = "tracing")]
        tracing::trace!(
            ?local_address,
            ?remote_address,
            "tcp connection established"
        );

        Ok(TcpStream {
            local_address,
            remote_address,
            stream
        })
    }
}

#[derive(Debug)]
pub struct TcpStream {
    local_address: SocketAddr,
    remote_address: SocketAddr,
    stream: std::net::TcpStream
}

impl Stream for TcpStream {
    #[inline(always)]
    fn local_address(&self) -> &SocketAddr {
        &self.local_address
    }

    #[inline(always)]
    fn remote_address(&self) -> &SocketAddr {
        &self.remote_address
    }

    #[inline]
    async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.stream.read(buf)?;

        #[cfg(feature = "tracing")]
        tracing::trace!(
            len = buf.len(),
            "read bytes from the tcp stream"
        );

        Ok(n)
    }

    #[inline]
    async fn read_exact(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
        self.stream.read_exact(buf)?;

        #[cfg(feature = "tracing")]
        tracing::trace!(
            len = buf.len(),
            "read bytes from the tcp stream"
        );

        Ok(())
    }

    #[inline]
    async fn write(&mut self, buf: &[u8]) -> std::io::Result<()> {
        #[cfg(feature = "tracing")]
        tracing::trace!(
            len = buf.len(),
            "send bytes to the tcp stream"
        );

        self.stream.write_all(buf)?;

        Ok(())
    }

    #[inline]
    async fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()?;

        Ok(())
    }
}
