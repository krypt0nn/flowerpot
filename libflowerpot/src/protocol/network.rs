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
use std::net::TcpStream;
use std::io::{Read, Write, ErrorKind};

#[cfg(feature = "encryption-chacha20")]
use chacha20::cipher::{KeyIvInit, StreamCipher};

use crate::crypto::base64;
use crate::crypto::key_exchange::{SecretKey, PublicKey};

use super::packets::{Packet, PacketDecodeError};

#[derive(Debug, thiserror::Error)]
pub enum PacketStreamError {
    #[error("stream error: {0}")]
    Stream(std::io::Error),

    #[error(transparent)]
    Packet(#[from] PacketDecodeError),

    #[error("unsupported protocol version: {0}")]
    UnsupportedProtocolVersion(u8),

    #[error("invalid ecdh public key")]
    InvalidPublicKey,

    #[error("remote party doesn't support any of requested encryption algorithms")]
    NoSupportedEncryption,

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
        fn scale<const N: usize>(input: &[u8], output: &mut [u8; N]) {
            let mut i = 0u8;
            let mut j = 0usize;

            let mut keyed_input = vec![0; input.len() + 1];

            keyed_input[1..input.len() + 1].copy_from_slice(input);

            while j < N {
                keyed_input[0] = i;

                let hash = blake3::keyed_hash(&[
                    129, 139, 171,  34, 143, 120,  62, 174,
                      2, 242, 158, 197,  36, 156, 246, 235,
                     13, 130, 199, 106,  55,  25, 141, 253,
                     84,   9,  91,  51, 161,  36,  37,  56
                ], &keyed_input);

                let n = (N - j).min(32);

                output[j..j + n].copy_from_slice(&hash.as_bytes()[..n]);

                i += 1;
                j += n;
            }
        }

        match algorithm {
            #[cfg(feature = "encryption-chacha20")]
            PacketStreamEncryption::ChaCha20 |
            PacketStreamEncryption::ChaCha12 |
            PacketStreamEncryption::ChaCha8 => {
                let mut key_scaled = [0; 32];
                let mut iv_scaled = [0; 12];

                scale(key, &mut key_scaled);
                scale(iv, &mut iv_scaled);

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

impl std::fmt::Debug for PacketStreamEncryptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ChaCha20(_) => f.debug_struct("ChaCha20").finish(),
            Self::ChaCha12(_) => f.debug_struct("ChaCha12").finish(),
            Self::ChaCha8(_)  => f.debug_struct("ChaCha8").finish()
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
    ///
    /// Default: `[chacha20, chacha12, chacha8]` if chacha20 encryption feature
    /// is enabled, otherwise `[]` (nothing).
    pub encryption_algorithms: Vec<PacketStreamEncryption>,

    /// Do not allow stream to be initialized if remote party doesn't support
    /// any of provided `encryption_algorithms`. If disabled, then connection
    /// will be established even if there's no encryption both nodes support,
    /// and connection will not be encrypted.
    ///
    /// This option has no effect if `encryption_algorithms` list is empty.
    ///
    /// Default: `true`.
    pub force_encryption: bool
}

impl Default for PacketStreamOptions {
    fn default() -> Self {
        Self {
            encryption_algorithms: vec![
                #[cfg(feature = "encryption-chacha20")]
                PacketStreamEncryption::ChaCha20,

                #[cfg(feature = "encryption-chacha20")]
                PacketStreamEncryption::ChaCha12,

                #[cfg(feature = "encryption-chacha20")]
                PacketStreamEncryption::ChaCha8
            ],

            force_encryption: true
        }
    }
}

impl AsRef<PacketStreamOptions> for PacketStreamOptions {
    #[inline(always)]
    fn as_ref(&self) -> &PacketStreamOptions {
        self
    }
}

#[derive(Default, Debug, Clone, Copy, PartialEq)]
pub struct PacketStreamStats {
    /// Total amount of uploaded (written) bytes.
    pub upload_total: u64,

    /// Total amount of downloaded (read) bytes.
    pub download_total: u64,

    /// Approximate bytes uploading (writing) speed per second.
    pub upload_rate: f64,

    /// Approximate bytes downloading (reading) speed per second.
    pub download_rate: f64
}

#[derive(Debug)]
pub struct PacketStream {
    stream: TcpStream,
    local_id: [u8; 32],
    peer_id: [u8; 32],
    shared_secret: [u8; 32],
    read_encryptor: Option<PacketStreamEncryptor>,
    write_encryptor: Option<PacketStreamEncryptor>,
    buf: Vec<u8>,
    peek_queue: VecDeque<Packet>,
    stats: PacketStreamStats
}

impl PacketStream {
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
    pub fn init(
        secret_key: impl AsRef<SecretKey>,
        options: &PacketStreamOptions,
        mut stream: TcpStream
    ) -> Result<Self, PacketStreamError> {
        let peer_addr = stream.peer_addr().ok();

        #[cfg(feature = "tracing")]
        tracing::trace!(
            ?peer_addr,
            ?options,
            "initializing packet stream connection"
        );

        // Prepare public key for key exchange.
        let secret_key = secret_key.as_ref();
        let public_key = secret_key.public_key().to_bytes();

        let local_id = blake3::keyed_hash(
            &Self::V1_ENDPOINT_ID_SALT,
            &public_key
        );

        // Prepare options byte.
        let mut options_byte = 0b00000000;

        for algorithm in &options.encryption_algorithms {
            options_byte |= match algorithm {
                #[cfg(feature = "encryption-chacha20")]
                PacketStreamEncryption::ChaCha20 => Self::V1_CHACHA20_ENCRYPTION,

                #[cfg(feature = "encryption-chacha20")]
                PacketStreamEncryption::ChaCha12 => Self::V1_CHACHA12_ENCRYPTION,

                #[cfg(feature = "encryption-chacha20")]
                PacketStreamEncryption::ChaCha8 => Self::V1_CHACHA8_ENCRYPTION,

                #[allow(unreachable_patterns)]
                _ => 0
            };
        }

        #[cfg(feature = "tracing")]
        tracing::trace!(
            ?peer_addr,
            local_id = base64::encode(local_id.as_bytes()),
            ?options,
            "send handshake"
        );

        // Send header and options.
        stream.write_all(&[
            Self::V1_HEADER,
            options_byte
        ]).map_err(PacketStreamError::Stream)?;

        // Send public key.
        stream.write_all(&public_key)
            .map_err(PacketStreamError::Stream)?;

        #[cfg(feature = "tracing")]
        tracing::trace!(
            ?peer_addr,
            local_id = base64::encode(local_id.as_bytes()),
            ?options,
            "read handshake"
        );

        // Read protocol version from the header byte.
        let mut buf = [0; 1];

        stream.read_exact(&mut buf)
            .map_err(PacketStreamError::Stream)?;

        if buf[0] != Self::V1_HEADER {
            return Err(PacketStreamError::UnsupportedProtocolVersion(buf[0]));
        }

        // Read options.
        let mut buf = [0; 1];

        stream.read_exact(&mut buf)
            .map_err(PacketStreamError::Stream)?;

        // Read public key.
        let mut public_key = [0; PublicKey::SIZE];

        stream.read_exact(&mut public_key)
            .map_err(PacketStreamError::Stream)?;

        let peer_id = blake3::keyed_hash(
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

        // Reject stream building if remote party doesn't support our requested
        // encryption algorithms and `force_encryption` option is enabled.
        if encryption_algorithm.is_none()
            && !options.encryption_algorithms.is_empty()
            && options.force_encryption
        {
            return Err(PacketStreamError::NoSupportedEncryption);
        }

        // Prepare read and write encryptors.
        let mut read_encryptor = match &encryption_algorithm {
            Some(algorithm) => {
                Some(PacketStreamEncryptor::new(
                    algorithm,
                    &shared_secret,
                    peer_id.as_bytes()
                ).ok_or(PacketStreamError::EncryptorBuildFailed)?)
            }

            None => None
        };

        let mut write_encryptor = match &encryption_algorithm {
            Some(algorithm) => {
                Some(PacketStreamEncryptor::new(
                    algorithm,
                    &shared_secret,
                    local_id.as_bytes()
                ).ok_or(PacketStreamError::EncryptorBuildFailed)?)
            }

            None => None
        };

        #[cfg(feature = "tracing")]
        tracing::trace!(
            ?peer_addr,
            local_id = base64::encode(local_id.as_bytes()),
            peer_id = base64::encode(peer_id.as_bytes()),
            shared_secret_image = base64::encode(shared_secret_image.as_bytes()),
            ?options,
            "send shared secret image"
        );

        // Send shared secret image.
        let mut buf: [u8; 32] = *shared_secret_image.as_bytes();

        if let Some(encryptor) = &mut write_encryptor {
            encryptor.apply(&mut buf);
        }

        stream.write_all(&buf)
            .map_err(PacketStreamError::Stream)?;

        // Read shared secret image.
        let mut buf = [0; 32];

        stream.read_exact(&mut buf)
            .map_err(PacketStreamError::Stream)?;

        if let Some(encryptor) = &mut read_encryptor {
            encryptor.apply(&mut buf);
        }

        #[cfg(feature = "tracing")]
        tracing::trace!(
            ?peer_addr,
            local_id = base64::encode(local_id.as_bytes()),
            peer_id = base64::encode(peer_id.as_bytes()),
            shared_secret_image = base64::encode(buf),
            ?options,
            "read shared secret image"
        );

        if &buf != shared_secret_image.as_bytes() {
            return Err(PacketStreamError::InvalidSharedSecretImage);
        }

        #[cfg(feature = "tracing")]
        tracing::trace!("enable non-blocking stream mode");

        stream.set_nonblocking(true)
            .map_err(PacketStreamError::Stream)?;

        #[cfg(feature = "tracing")]
        tracing::info!(
            ?encryption_algorithm,
            "packet stream connection initialized"
        );

        Ok(Self {
            stream,
            local_id: local_id.into(),
            peer_id: peer_id.into(),
            shared_secret,
            read_encryptor,
            write_encryptor,
            buf: Vec::new(),
            peek_queue: VecDeque::new(),
            stats: PacketStreamStats::default()
        })
    }

    /// Get socket address of the local endpoint.
    #[inline]
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.stream.local_addr()
    }

    /// Get socket address of the remote endpoint.
    #[inline]
    pub fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        self.stream.peer_addr()
    }

    /// Get unique identifier of the local stream's endpoint.
    ///
    /// It is derived from the remote party's public key and can be used to
    /// keep only one connection with the same remote endpoint at once.
    #[inline]
    pub const fn local_id(&self) -> &[u8; 32] {
        &self.local_id
    }

    /// Get unique identifier of the peer stream's endpoint.
    ///
    /// It is derived from the remote party's public key and can be used to
    /// keep only one connection with the same remote endpoint at once.
    #[inline]
    pub const fn peer_id(&self) -> &[u8; 32] {
        &self.peer_id
    }

    /// Get shared secret for this stream.
    #[inline]
    pub const fn shared_secret(&self) -> &[u8; 32] {
        &self.shared_secret
    }

    /// Get packet stream stats.
    #[inline]
    pub const fn stats(&self) -> &PacketStreamStats {
        &self.stats
    }

    /// Try to send a packet.
    ///
    /// This is a blocking method which will return only when the whole packet
    /// buffer is sent to the remote peer.
    pub fn send(
        &mut self,
        packet: impl AsRef<Packet>
    ) -> Result<(), PacketStreamError> {
        let mut packet = packet.as_ref()
            .to_bytes();

        let length = packet.len();

        if length > u32::MAX as usize {
            return Err(PacketStreamError::PacketTooLarge);
        }

        #[cfg(feature = "tracing")]
        tracing::trace!(
            ?length,
            local_id = base64::encode(self.local_id),
            peer_id = base64::encode(self.peer_id),
            stats = ?self.stats,
            "write packet"
        );

        let mut length: [u8; 4] = (length as u32).to_le_bytes();

        if let Some(encryptor) = &mut self.write_encryptor {
            encryptor.apply(&mut length);
            encryptor.apply(&mut packet);
        }

        let now = std::time::Instant::now();

        let mut i = 0;

        while i < 4 {
            match self.stream.write(&length[i..]) {
                Ok(n) => i += n,

                Err(err) if err.kind() == ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }

                Err(err) => return Err(PacketStreamError::Stream(err))
            }
        }

        i = 0;

        while i < packet.len() {
            match self.stream.write(&packet[i..]) {
                Ok(n) => i += n,

                Err(err) if err.kind() == ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }

                Err(err) => return Err(PacketStreamError::Stream(err))
            }
        }

        let elapsed = now.elapsed().as_secs_f64();

        let upload_rate = (packet.len() + 4) as f64 / elapsed;

        self.stats.upload_total += packet.len() as u64 + 4;
        self.stats.upload_rate = (upload_rate * 2.0 + self.stats.upload_rate) / 3.0;

        Ok(())
    }

    /// Try to receive a packet.
    ///
    /// This method will check if remote peer tries to send us a packet, and if
    /// so, then it will block current thread until the whole packet is read.
    /// Otherwise, if there's no data to read, the method will return
    /// immediately with `Ok(None)` and won't block the thread.
    pub fn try_recv(&mut self) -> Result<Option<Packet>, PacketStreamError> {
        // Try to peek a packet from the queue.
        if let Some(packet) = self.peek_queue.pop_front() {
            return Ok(Some(packet));
        }

        // Try to read a new packet in chunks of 4096 bytes.
        let mut buf = [0; 4096];
        let mut read = 0;

        let now = std::time::Instant::now();

        loop {
            let n = self.buf.len();

            // Check if we know size of the upcoming packet.
            if n > 4 {
                // Read its size.
                let length = u32::from_le_bytes([
                    self.buf[0], self.buf[1], self.buf[2], self.buf[3]
                ]) as usize;

                // If we already have the whole packet.
                if n >= length + 4 {
                    #[cfg(feature = "tracing")]
                    tracing::trace!(
                        ?length,
                        local_id = base64::encode(self.local_id),
                        peer_id = base64::encode(self.peer_id),
                        stats = ?self.stats,
                        "read packet"
                    );

                    // Try to decode it.
                    let packet = Packet::from_bytes(&self.buf[4..length + 4]);

                    // Remove the packet bytes even if the packet is invalid.
                    self.buf.drain(..length + 4);

                    // And return it.
                    return Ok(Some(packet.map_err(PacketStreamError::Packet)?));
                }
            }

            // Otherwise if we don't have the whole packet yet we need to read
            // it from the stream.
            match self.stream.read(&mut buf) {
                // If we've read some part of the packet.
                Ok(n) => {
                    // Decrypt it if needed.
                    if let Some(encryptor) = &mut self.read_encryptor {
                        encryptor.apply(&mut buf[..n]);
                    }

                    // And write it to the buffer.
                    self.buf.extend(&buf[..n]);

                    read += n as u64;
                },

                // Otherwise, if stream doesn't contain any more data - then
                // return from method saying that there's no packet to read yet.
                Err(err) if err.kind() == ErrorKind::WouldBlock => {
                    if read > 0 {
                        let elapsed = now.elapsed().as_secs_f64();

                        let download_rate = read as f64 / elapsed;

                        self.stats.download_total += read;
                        self.stats.download_rate = (download_rate * 2.0 + self.stats.download_rate) / 3.0;
                    }

                    return Ok(None);
                }

                // Propagate the error.
                Err(err) => return Err(PacketStreamError::Stream(err))
            }
        }
    }

    /// Receive packets and send them to the provided callback until it returns
    /// `true`. Packet which got `true` from the callback will be returned by
    /// this method. Other packets will be put into a queue of the `try_recv`
    /// method so they won't be missed.
    ///
    /// This is a blocking method. It will try to receive packets from remote
    /// peer until appropriate one is received.
    ///
    /// This method can be used to search for a requested packet.
    pub fn peek(
        &mut self,
        mut callback: impl FnMut(&Packet) -> bool
    ) -> Result<Packet, PacketStreamError> {
        let mut peek_queue = Vec::new();

        loop {
            let Some(packet) = self.try_recv()? else {
                std::thread::sleep(std::time::Duration::from_millis(10));

                continue;
            };

            if callback(&packet) {
                self.peek_queue.extend(peek_queue);

                return Ok(packet);
            }

            peek_queue.push(packet);
        }
    }
}
