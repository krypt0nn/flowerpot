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

use std::collections::VecDeque;
use std::net::SocketAddr;

#[cfg(feature = "encryption-chacha20")]
use chacha20::cipher::{KeyIvInit, StreamCipher};

use crate::crypto::key_exchange::{SecretKey, PublicKey};
use crate::network::Stream;

use super::{Packet, PacketError};

#[derive(Debug, thiserror::Error)]
pub enum PacketStreamError {
    #[error("stream error: {0}")]
    Stream(std::io::Error),

    #[error(transparent)]
    Packet(#[from] PacketError),

    #[error("unsupported protocol version: {0}")]
    UnsupportedProtocolVersion(u8),

    #[error("invalid ecdh public key")]
    InvalidPublicKey,

    #[error("failed to build data stream encryptor")]
    EncryptorBuildFailed,

    #[error("remote endpoint sent invalid shared secret image")]
    InvalidSharedSecretImage,

    #[error("packet is too large to be sent over the network")]
    PacketTooLarge
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PacketStreamEncryption {
    ChaCha20,
    ChaCha12,
    ChaCha8
}

pub enum PacketStreamEncryptor {
    #[cfg(feature = "encryption-chacha20")]
    ChaCha20(chacha20::ChaCha20),

    #[cfg(feature = "encryption-chacha20")]
    ChaCha12(chacha20::ChaCha12),

    #[cfg(feature = "encryption-chacha20")]
    ChaCha8(chacha20::ChaCha8)
}

impl PacketStreamEncryptor {
    /// Try to build new stream encryptor with provided algorithm, key and
    /// initialization vector.
    pub fn new(
        algorithm: &PacketStreamEncryption,
        key: &[u8],
        iv: &[u8]
    ) -> Option<Self> {
        match algorithm {
            #[cfg(feature = "encryption-chacha20")]
            PacketStreamEncryption::ChaCha20 |
            PacketStreamEncryption::ChaCha12 |
            PacketStreamEncryption::ChaCha8 => {
                let mut key_scaled = [0; 32];
                let mut iv_scaled = [0; 32];

                if key.len() == 32 {
                    key_scaled.copy_from_slice(key);
                } else {
                    key_scaled.copy_from_slice(blake3::hash(key).as_bytes());
                }

                if iv.len() == 32 {
                    iv_scaled.copy_from_slice(iv);
                } else {
                    iv_scaled.copy_from_slice(blake3::hash(iv).as_bytes());
                }

                match algorithm {
                    PacketStreamEncryption::ChaCha20 => {
                        let encryptor = chacha20::ChaCha20::new_from_slices(
                            &key_scaled,
                            &iv_scaled
                        ).ok()?;

                        Some(Self::ChaCha20(encryptor))
                    }

                    PacketStreamEncryption::ChaCha12 => {
                        let encryptor = chacha20::ChaCha12::new_from_slices(
                            &key_scaled,
                            &iv_scaled
                        ).ok()?;

                        Some(Self::ChaCha12(encryptor))
                    }

                    PacketStreamEncryption::ChaCha8 => {
                        let encryptor = chacha20::ChaCha8::new_from_slices(
                            &key_scaled,
                            &iv_scaled
                        ).ok()?;

                        Some(Self::ChaCha8(encryptor))
                    }
                }
            }

            #[allow(unreachable_patterns)]
            _ => None
        }
    }

    /// Apply stream encryption to the provided buffer.
    pub fn apply(&mut self, buf: &mut [u8]) {
        match self {
            #[cfg(feature = "encryption-chacha20")]
            Self::ChaCha20(encryptor) => encryptor.apply_keystream(buf),

            #[cfg(feature = "encryption-chacha20")]
            Self::ChaCha12(encryptor) => encryptor.apply_keystream(buf),

            #[cfg(feature = "encryption-chacha20")]
            Self::ChaCha8(encryptor)  => encryptor.apply_keystream(buf),

            #[allow(unreachable_patterns)]
            _ => ()
        }
    }
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Hash)]
pub struct PacketStreamOptions {
    /// List of encryption algorithms which can be used by the packet stream.
    ///
    /// The packet stream will choose the best option supported by both parties.
    ///
    /// Set this value as an empty vector if you don't want to encrypt the
    /// transport stream.
    ///
    /// > **Note**: encryption is not needed for blockchain applications since
    /// > blockchain by its nature is open for everybody. This option is mainly
    /// > needed to hide your traffic.
    pub encryption_algorithms: Vec<PacketStreamEncryption>
}

/// Abstraction over a transport protocol data stream which supports packets
/// sending and receiving, endpoint validation and optional stream encryption.
pub struct PacketStream<S: Stream> {
    stream: S,
    endpoint_id: [u8; 32],
    shared_secret: [u8; 32],
    read_encryptor: Option<PacketStreamEncryptor>,
    write_encryptor: Option<PacketStreamEncryptor>,
    peek_queue: VecDeque<Packet>
}

impl<S: Stream> PacketStream<S> {
    pub const V1_HEADER: u8 = 0;

    pub const V1_CHACHA20_ENCRYPTION: u8 = 0b00000001;
    pub const V1_CHACHA12_ENCRYPTION: u8 = 0b00000010;
    pub const V1_CHACHA8_ENCRYPTION: u8  = 0b00000100;

    // Salts were randomly generated using random.org service.

    pub const V1_ENDPOINT_ID_SALT: [u8; 32] = [
        140,  51,  88,  13, 199, 162, 187,  90,
        203, 253, 146, 211,  38, 233,  64,  94,
         22, 149,  33, 125, 120, 238, 151, 247,
        127, 246, 157, 130, 236, 197, 255,  50
    ];

    pub const V1_SHARED_SECRET_IMAGE_SALT: [u8; 32] = [
        235, 214, 153, 167,  37, 128, 221,  65,
        240, 229, 201,  26,  23, 135,  48, 161,
        107, 251, 212,  57, 252,  55, 131,  60,
        190,   5,  67,  43,  71, 194, 198, 159
    ];

    /// Initialize packet stream connection using the underlying transport
    /// stream.
    ///
    /// This method will exchange some handshake info, read incoming data and
    /// if handshake was successful - provide simple interface to send and
    /// receive packets over the network.
    pub async fn init(
        secret_key: impl AsRef<SecretKey>,
        options: PacketStreamOptions,
        mut stream: S
    ) -> Result<Self, PacketStreamError> {
        #[cfg(feature = "tracing")]
        tracing::trace!(
            ?options,
            "initializing packet stream connection"
        );

        // Prepare public key for key exchange.
        let secret_key = secret_key.as_ref();
        let public_key = secret_key.public_key().to_bytes();

        // Prepare options byte.
        let mut options_byte = 0b00000000;

        for algorithm in &options.encryption_algorithms {
            options_byte |= match algorithm {
                #[cfg(feature = "encryption-chacha20")]
                PacketStreamEncryption::ChaCha20 => Self::V1_CHACHA20_ENCRYPTION,

                #[cfg(feature = "encryption-chacha20")]
                PacketStreamEncryption::ChaCha12 => Self::V1_CHACHA12_ENCRYPTION,

                #[cfg(feature = "encryption-chacha20")]
                PacketStreamEncryption::ChaCha8  => Self::V1_CHACHA8_ENCRYPTION,

                #[allow(unreachable_patterns)]
                _ => 0
            };
        }

        // Send header and options.
        stream.write(&[
            Self::V1_HEADER,
            options_byte
        ]).await.map_err(PacketStreamError::Stream)?;

        // Send public key.
        stream.write(&public_key).await
            .map_err(PacketStreamError::Stream)?;

        stream.flush().await
            .map_err(PacketStreamError::Stream)?;

        // Read protocol version from the header byte.
        let mut buf = [0; 1];

        stream.read_exact(&mut buf).await
            .map_err(PacketStreamError::Stream)?;

        if buf[0] != Self::V1_HEADER {
            return Err(PacketStreamError::UnsupportedProtocolVersion(buf[0]));
        }

        // Read options.
        let mut buf = [0; 1];

        stream.read_exact(&mut buf).await
            .map_err(PacketStreamError::Stream)?;

        // Read public key.
        let mut public_key = [0; PublicKey::SIZE];

        stream.read_exact(&mut public_key).await
            .map_err(PacketStreamError::Stream)?;

        let endpoint_id = blake3::keyed_hash(
            &Self::V1_ENDPOINT_ID_SALT,
            &public_key
        );

        let public_key = PublicKey::from_bytes(&public_key)
            .ok_or(PacketStreamError::InvalidPublicKey)?;

        // Prepare shared secret.
        let shared_secret = secret_key.shared_secret(&public_key);

        let shared_secret_image = blake3::keyed_hash(
            &Self::V1_SHARED_SECRET_IMAGE_SALT,
            &shared_secret
        );

        // Decode options.
        let mut supported_encryption = Vec::with_capacity(3);

        #[cfg(feature = "encryption-chacha20")]
        if buf[0] & Self::V1_CHACHA20_ENCRYPTION == Self::V1_CHACHA20_ENCRYPTION {
            supported_encryption.push(PacketStreamEncryption::ChaCha20);
        }

        #[cfg(feature = "encryption-chacha20")]
        if buf[0] & Self::V1_CHACHA12_ENCRYPTION == Self::V1_CHACHA12_ENCRYPTION {
            supported_encryption.push(PacketStreamEncryption::ChaCha12);
        }

        #[cfg(feature = "encryption-chacha20")]
        if buf[0] & Self::V1_CHACHA8_ENCRYPTION == Self::V1_CHACHA8_ENCRYPTION {
            supported_encryption.push(PacketStreamEncryption::ChaCha8);
        }

        // Choose common encryption algorithm.
        let mut encryption_algorithm = None;

        for algorithm in &options.encryption_algorithms {
            if supported_encryption.contains(algorithm) {
                encryption_algorithm = Some(*algorithm);

                break;
            }
        }

        // Prepare read and write encryptors.
        let mut read_encryptor = match &encryption_algorithm {
            Some(algorithm) => {
                Some(PacketStreamEncryptor::new(
                    algorithm,
                    &shared_secret,
                    endpoint_id.as_bytes()
                ).ok_or(PacketStreamError::EncryptorBuildFailed)?)
            }

            None => None
        };

        let mut write_encryptor = match &encryption_algorithm {
            Some(algorithm) => {
                Some(PacketStreamEncryptor::new(
                    algorithm,
                    &shared_secret,
                    endpoint_id.as_bytes()
                ).ok_or(PacketStreamError::EncryptorBuildFailed)?)
            }

            None => None
        };

        // Send shared secret image.
        let mut buf: [u8; 32] = *shared_secret_image.as_bytes();

        if let Some(encryptor) = &mut write_encryptor {
            encryptor.apply(&mut buf);
        }

        stream.write(&buf).await
            .map_err(PacketStreamError::Stream)?;

        stream.flush().await
            .map_err(PacketStreamError::Stream)?;

        // Read shared secret image.
        let mut buf = [0; 32];

        stream.read_exact(&mut buf).await
            .map_err(PacketStreamError::Stream)?;

        if let Some(encryptor) = &mut read_encryptor {
            encryptor.apply(&mut buf);
        }

        if &buf != shared_secret_image.as_bytes() {
            return Err(PacketStreamError::InvalidSharedSecretImage);
        }

        #[cfg(feature = "tracing")]
        tracing::info!(
            ?encryption_algorithm,
            "packet stream connection initialized"
        );

        Ok(Self {
            stream,
            endpoint_id: endpoint_id.into(),
            shared_secret,
            read_encryptor,
            write_encryptor,
            peek_queue: VecDeque::new()
        })
    }

    /// Get socket address of the local endpoint.
    #[inline]
    pub fn local_address(&self) -> &SocketAddr {
        self.stream.local_address()
    }

    /// Get socket address of the remote endpoint.
    #[inline]
    pub fn remote_address(&self) -> &SocketAddr {
        self.stream.remote_address()
    }

    /// Get unique identifier of the stream's remote endpoint.
    ///
    /// It is derived from the remote party's public key and can be used to
    /// keep only one connection with the same remote endpoint at once.
    #[inline(always)]
    pub const fn endpoint_id(&self) -> &[u8; 32] {
        &self.endpoint_id
    }

    /// Get shared secret for this stream.
    #[inline(always)]
    pub const fn shared_secret(&self) -> &[u8; 32] {
        &self.shared_secret
    }

    /// Send packet.
    pub async fn send(
        &mut self,
        packet: impl AsRef<Packet>
    ) -> Result<(), PacketStreamError> {
        let mut packet = packet.as_ref()
            .to_bytes()
            .map_err(PacketStreamError::Packet)?;

        let length = packet.len();

        if length > u32::MAX as usize {
            return Err(PacketStreamError::PacketTooLarge);
        }

        #[cfg(feature = "tracing")]
        tracing::trace!(?length, "send packet");

        let mut length: [u8; 4] = (length as u32).to_le_bytes();

        if let Some(encryptor) = &mut self.write_encryptor {
            encryptor.apply(&mut length);
            encryptor.apply(&mut packet);
        }

        self.stream.write(&length).await
            .map_err(PacketStreamError::Stream)?;

        self.stream.write(&packet).await
            .map_err(PacketStreamError::Stream)?;

        self.stream.flush().await
            .map_err(PacketStreamError::Stream)?;

        Ok(())
    }

    /// Receive packet.
    pub async fn recv(&mut self) -> Result<Packet, PacketStreamError> {
        if let Some(packet) = self.peek_queue.pop_front() {
            return Ok(packet);
        }

        let mut length = [0; 4];

        self.stream.read_exact(&mut length).await
            .map_err(PacketStreamError::Stream)?;

        let mut packet = vec![0; u32::from_le_bytes(length) as usize];

        #[cfg(feature = "tracing")]
        tracing::trace!(length = packet.len(), "recv packet");

        self.stream.read_exact(&mut packet).await
            .map_err(PacketStreamError::Stream)?;

        if let Some(encryptor) = &mut self.read_encryptor {
            encryptor.apply(&mut length);
            encryptor.apply(&mut packet);
        }

        let packet = Packet::from_bytes(packet)
            .map_err(PacketStreamError::Packet)?;

        Ok(packet)
    }

    /// Receive packets and send them to the provided callback until it returns
    /// `true`. Packet which got `true` from the callback will be returned by
    /// this method. Other packets will be put into a queue of the `recv`
    /// method.
    ///
    /// This method can be used to search for a requested packet.
    pub async fn peek(
        &mut self,
        mut callback: impl FnMut(&Packet) -> bool
    ) -> Result<Packet, PacketStreamError> {
        let mut peek_queue = Vec::new();

        loop {
            let packet = self.recv().await?;

            if callback(&packet) {
                self.peek_queue.extend(peek_queue);

                return Ok(packet);
            }

            peek_queue.push(packet);
        }
    }
}
