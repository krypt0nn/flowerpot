use base64::engine::{GeneralPurpose, GeneralPurposeConfig};
use base64::alphabet::URL_SAFE;
use base64::Engine;
use k256::ecdsa::signature::hazmat::PrehashVerifier;

const BASE64_ENGINE: GeneralPurpose = GeneralPurpose::new(
    &URL_SAFE,
    GeneralPurposeConfig::new()
);

#[inline]
pub fn base64_encode(data: impl AsRef<[u8]>) -> String {
    BASE64_ENGINE.encode(data)
}

#[inline]
pub fn base64_decode(
    data: impl AsRef<[u8]>
) -> Result<Vec<u8>, base64::DecodeError> {
    BASE64_ENGINE.decode(data)
}

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hash(pub [u8; 32]);

impl Hash {
    #[inline]
    pub fn from_slice(value: impl AsRef<[u8]>) -> Self {
        Self::from(blake3::hash(value.as_ref()))
    }

    #[inline]
    pub fn to_base64(&self) -> String {
        base64_encode(self.0)
    }

    pub fn from_base64(hash: impl AsRef<[u8]>) -> Option<Self> {
        match base64_decode(hash) {
            Ok(hash) if hash.len() == 32 => {
                let mut result = Self::default();

                result.0.copy_from_slice(&hash);

                Some(result)
            }

            _ => None
        }
    }
}

impl From<blake3::Hash> for Hash {
    #[inline]
    fn from(value: blake3::Hash) -> Self {
        Self(*value.as_bytes())
    }
}

impl From<[u8; 32]> for Hash {
    #[inline(always)]
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey(k256::ecdsa::VerifyingKey);

impl PublicKey {
    pub fn to_bytes(&self) -> [u8; 33] {
        let mut bytes = [0; 33];

        bytes.copy_from_slice(&self.0.to_sec1_bytes());

        bytes
    }

    pub fn from_bytes(public_key: impl AsRef<[u8]>) -> Option<Self> {
        k256::ecdsa::VerifyingKey::from_sec1_bytes(public_key.as_ref()).ok().map(Self)
    }

    #[inline]
    pub fn to_base64(&self) -> String {
        base64_encode(self.to_bytes())
    }

    pub fn from_base64(public_key: impl AsRef<[u8]>) -> Option<Self> {
        Self::from_bytes(base64_decode(public_key).ok()?)
    }
}

impl From<k256::ecdsa::VerifyingKey> for PublicKey {
    #[inline(always)]
    fn from(value: k256::ecdsa::VerifyingKey) -> Self {
        Self(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretKey(k256::ecdsa::SigningKey);

impl SecretKey {
    pub fn random(rng: &mut impl k256::schnorr::CryptoRngCore) -> Self {
        Self(k256::ecdsa::SigningKey::random(rng))
    }

    #[inline]
    pub fn public_key(&self) -> PublicKey {
        PublicKey(*self.0.verifying_key())
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        let mut bytes = [0; 32];

        let secret = self.0.to_bytes()
            .to_vec()
            .into_boxed_slice();

        bytes.copy_from_slice(&secret);

        bytes
    }

    pub fn from_bytes(secret_key: impl AsRef<[u8]>) -> Option<Self> {
        k256::ecdsa::SigningKey::from_slice(secret_key.as_ref()).ok().map(Self)
    }

    #[inline]
    pub fn to_base64(&self) -> String {
        base64_encode(self.to_bytes())
    }

    pub fn from_base64(secret_key: impl AsRef<[u8]>) -> Option<Self> {
        Self::from_bytes(base64_decode(secret_key).ok()?)
    }
}

impl From<k256::ecdsa::SigningKey> for SecretKey {
    #[inline(always)]
    fn from(value: k256::ecdsa::SigningKey) -> Self {
        Self(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature(k256::ecdsa::Signature, k256::ecdsa::RecoveryId);

impl Signature {
    pub fn create(
        secret_key: &SecretKey,
        data_hash: impl Into<Hash>
    ) -> Result<Self, k256::ecdsa::Error> {
        let data_hash: Hash = data_hash.into();

        let (sign, id) = secret_key.0.sign_prehash_recoverable(&data_hash.0)?;

        Ok(Self(sign, id))
    }

    pub fn verify(&self, data_hash: impl Into<Hash>) -> Result<(bool, PublicKey), k256::ecdsa::Error> {
        let data_hash: Hash = data_hash.into();

        let verifying_key = k256::ecdsa::VerifyingKey::recover_from_prehash(
            &data_hash.0,
            &self.0,
            self.1
        )?;

        let valid = verifying_key.verify_prehash(&data_hash.0, &self.0).is_ok();

        Ok((valid, PublicKey(verifying_key)))
    }

    pub fn to_bytes(&self) -> [u8; 65] {
        let mut sign = [0; 65];

        sign[..64].copy_from_slice(&self.0.to_vec());
        sign[64] = self.1.to_byte();

        sign
    }

    pub fn from_bytes(sign: impl AsRef<[u8]>) -> Option<Self> {
        let sign = sign.as_ref();
        let n = sign.len();

        let recovery_id = k256::ecdsa::RecoveryId::from_byte(sign[n - 1])?;
        let sign = k256::ecdsa::Signature::from_slice(&sign[..n - 1]).ok()?;

        Some(Self(sign, recovery_id))
    }

    #[inline]
    pub fn to_base64(&self) -> String {
        base64_encode(self.to_bytes())
    }

    pub fn from_base64(sign: impl AsRef<[u8]>) -> Option<Self> {
        Self::from_bytes(base64_decode(sign).ok()?)
    }
}
