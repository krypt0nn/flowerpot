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

use k256::ecdsa::signature::hazmat::PrehashVerifier;

use super::base64;
use super::hash::Hash;

/// Signature signing key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningKey(k256::ecdsa::SigningKey);

impl SigningKey {
    /// Bytes length of the signature signing key.
    pub const SIZE: usize = 32;

    /// Generate new random signature signing key.
    #[inline]
    pub fn random(rng: &mut impl k256::schnorr::CryptoRngCore) -> Self {
        Self(k256::ecdsa::SigningKey::random(rng))
    }

    #[inline]
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey(*self.0.verifying_key())
    }

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let secret = self.0.to_bytes()
            .to_vec();

        debug_assert_eq!(secret.len(), Self::SIZE);

        let mut bytes = [0; Self::SIZE];

        bytes.copy_from_slice(&secret);

        bytes
    }

    pub fn from_bytes(secret_key: &[u8; Self::SIZE]) -> Option<Self> {
        k256::ecdsa::SigningKey::from_slice(secret_key).ok().map(Self)
    }

    #[inline]
    pub fn to_base64(&self) -> String {
        base64::encode(self.to_bytes())
    }

    pub fn from_base64(secret_key: impl AsRef<[u8]>) -> Option<Self> {
        let secret_key = base64::decode(secret_key).ok()?;

        if secret_key.len() != Self::SIZE {
            return None;
        }

        let mut buf = [0; Self::SIZE];

        buf.copy_from_slice(&secret_key[..Self::SIZE]);

        Self::from_bytes(&buf)
    }
}

impl AsRef<SigningKey> for SigningKey {
    #[inline(always)]
    fn as_ref(&self) -> &SigningKey {
        self
    }
}

impl From<k256::ecdsa::SigningKey> for SigningKey {
    #[inline(always)]
    fn from(value: k256::ecdsa::SigningKey) -> Self {
        Self(value)
    }
}

impl std::fmt::Display for SigningKey {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_base64())
    }
}

/// Signature verifying key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyingKey(k256::ecdsa::VerifyingKey);

impl VerifyingKey {
    /// Bytes length of the signature verifying key.
    pub const SIZE: usize = 33;

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let buf = self.0.to_sec1_bytes();

        debug_assert_eq!(buf.len(), Self::SIZE);

        let mut bytes = [0; Self::SIZE];

        bytes.copy_from_slice(&buf);

        bytes
    }

    pub fn from_bytes(public_key: &[u8; Self::SIZE]) -> Option<Self> {
        k256::ecdsa::VerifyingKey::from_sec1_bytes(public_key).ok().map(Self)
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

impl AsRef<VerifyingKey> for VerifyingKey {
    #[inline(always)]
    fn as_ref(&self) -> &VerifyingKey {
        self
    }
}

impl From<k256::ecdsa::VerifyingKey> for VerifyingKey {
    #[inline(always)]
    fn from(value: k256::ecdsa::VerifyingKey) -> Self {
        Self(value)
    }
}

impl std::fmt::Display for VerifyingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_base64())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature(k256::ecdsa::Signature, k256::ecdsa::RecoveryId);

impl Signature {
    /// Bytes length of the signature.
    pub const SIZE: usize = 65;

    /// Sign provided data using signing key.
    pub fn create(
        signing_key: impl AsRef<SigningKey>,
        hash: impl AsRef<Hash>
    ) -> Result<Self, k256::ecdsa::Error> {
        let (sign, id) = signing_key.as_ref().0
            .sign_prehash_recoverable(hash.as_ref().as_bytes())?;

        Ok(Self(sign, id))
    }

    /// Verify that signature is made for the provided data slice, and restore
    /// its author's verifying key.
    pub fn verify(
        &self,
        hash: impl AsRef<Hash>
    ) -> Result<(bool, VerifyingKey), k256::ecdsa::Error> {
        let hash = hash.as_ref();

        let public_key = k256::ecdsa::VerifyingKey::recover_from_prehash(
            hash.as_bytes(),
            &self.0,
            self.1
        )?;

        let is_valid = public_key.verify_prehash(
            hash.as_bytes(),
            &self.0
        ).is_ok();

        Ok((is_valid, VerifyingKey(public_key)))
    }

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let buf = self.0.to_vec();

        debug_assert_eq!(buf.len(), Self::SIZE - 1);

        let mut sign = [0; Self::SIZE];

        sign[..Self::SIZE - 1].copy_from_slice(&buf);
        sign[Self::SIZE - 1] = self.1.to_byte();

        sign
    }

    pub fn from_bytes(sign: &[u8; Self::SIZE]) -> Option<Self> {
        let sign = sign.as_ref();

        let recovery_id = k256::ecdsa::RecoveryId::from_byte(sign[Self::SIZE - 1])?;
        let sign = k256::ecdsa::Signature::from_slice(&sign[..Self::SIZE - 1]).ok()?;

        Some(Self(sign, recovery_id))
    }

    #[inline]
    pub fn to_base64(&self) -> String {
        base64::encode(self.to_bytes())
    }

    pub fn from_base64(sign: impl AsRef<[u8]>) -> Option<Self> {
        let sign = base64::decode(sign).ok()?;

        if sign.len() != Self::SIZE {
            return None;
        }

        let mut buf = [0; Self::SIZE];

        buf.copy_from_slice(&sign);

        Self::from_bytes(&buf)
    }
}

impl std::fmt::Display for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_base64())
    }
}

#[test]
fn test() -> Result<(), k256::ecdsa::Error> {
    use rand_chacha::rand_core::SeedableRng;

    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(123);

    let signing_key = SigningKey::random(&mut rng);
    let verifying_key = signing_key.verifying_key();

    let signing_key = SigningKey::from_base64(signing_key.to_base64()).unwrap();
    let verifying_key = VerifyingKey::from_base64(verifying_key.to_base64()).unwrap();

    let hash = Hash::calc(b"test");

    let sign = Signature::create(signing_key, hash)?;
    let sign = Signature::from_base64(sign.to_base64()).unwrap();

    assert_eq!(sign.verify(hash)?, (true, verifying_key));

    Ok(())
}
