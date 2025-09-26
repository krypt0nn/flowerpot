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

use super::base64;

/// Secret key of the key exchange protocol.
///
/// > **Note**: to keep the protocol secure you should never use the same secret
/// > key for multiple key exchanges. It is expected that a new, random key is
/// > generated every time.
pub struct SecretKey(k256::ecdh::EphemeralSecret);

impl SecretKey {
    /// Key exchange hash salt.
    ///
    /// Salt value was randomly generated using random.org service.
    pub const SALT: [u8; 32] = [
         20, 160,  28, 119, 111,  25, 178, 249,
        152, 100, 103,  76, 168, 239, 116, 134,
        137, 241, 219, 175, 196, 216,  61, 227,
        170, 192, 145, 228,  73,   7, 150, 224
    ];

    /// Generate new random secret key.
    #[inline]
    pub fn random(rng: &mut impl k256::schnorr::CryptoRngCore) -> Self {
        Self(k256::ecdh::EphemeralSecret::random(rng))
    }

    #[inline]
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.public_key())
    }

    /// Calculate shared secret between the current secret key and provided
    /// public key.
    pub fn shared_secret(&self, public_key: impl AsRef<PublicKey>) -> [u8; 32] {
        let shared_secret = self.0.diffie_hellman(&public_key.as_ref().0);

        *blake3::keyed_hash(
            &Self::SALT,
            shared_secret.raw_secret_bytes().as_slice()
        ).as_bytes()
    }
}

impl AsRef<SecretKey> for SecretKey {
    #[inline(always)]
    fn as_ref(&self) -> &SecretKey {
        self
    }
}

impl From<k256::ecdh::EphemeralSecret> for SecretKey {
    #[inline(always)]
    fn from(value: k256::ecdh::EphemeralSecret) -> Self {
        Self(value)
    }
}

/// Public key of the key exchange protocol.
pub struct PublicKey(k256::PublicKey);

impl PublicKey {
    /// Bytes length of the key exchange protocol's public key.
    pub const SIZE: usize = 32;

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let buf = self.0.to_sec1_bytes();

        debug_assert_eq!(buf.len(), Self::SIZE);

        let mut bytes = [0; Self::SIZE];

        bytes.copy_from_slice(&buf);

        bytes
    }

    pub fn from_bytes(public_key: &[u8; Self::SIZE]) -> Option<Self> {
        k256::PublicKey::from_sec1_bytes(public_key).ok().map(Self)
    }

    #[inline]
    pub fn to_base64(&self) -> String {
        base64::encode(self.to_bytes())
    }

    pub fn from_base64(public_key: impl AsRef<[u8]>) -> Option<Self> {
        let public_key = base64::decode(public_key).ok()?;

        if public_key.len() != Self::SIZE {
            return None;
        }

        let mut buf = [0; Self::SIZE];

        buf.copy_from_slice(&public_key[..Self::SIZE]);

        Self::from_bytes(&buf)
    }
}

impl AsRef<PublicKey> for PublicKey {
    #[inline(always)]
    fn as_ref(&self) -> &PublicKey {
        self
    }
}

impl From<k256::PublicKey> for PublicKey {
    #[inline(always)]
    fn from(value: k256::PublicKey) -> Self {
        Self(value)
    }
}

impl std::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_base64())
    }
}

#[test]
fn test() {
    use rand_chacha::rand_core::SeedableRng;

    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(123);

    let secret_1 = SecretKey::random(&mut rng);
    let secret_2 = SecretKey::random(&mut rng);

    let public_1 = secret_1.public_key().to_base64();
    let public_2 = secret_2.public_key().to_base64();

    let public_1 = PublicKey::from_base64(public_1).unwrap();
    let public_2 = PublicKey::from_base64(public_2).unwrap();

    let shared_1 = secret_1.shared_secret(public_2);
    let shared_2 = secret_2.shared_secret(public_1);

    assert_eq!(shared_1, shared_2);
}
