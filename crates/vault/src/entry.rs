use std::collections::HashMap;

use data_encoding::{BASE32, BASE32_NOPAD};
use hmac::{Hmac, Mac};
use niceotp_protocol::Sealed;
use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use url::Url;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto::{aad, open_raw, seal_raw};
use crate::{Error, Result, VaultKey};

const MAX_ENTRY_BYTES: usize = 16 * 1024;

/// Plaintext exists only inside the unlocked client. No `Debug` implementation.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub name: String,
    pub account: String,
    pub issuer: String,
    pub secret: String,
    pub algorithm: String,
    pub digits: u32,
    pub period: u64,
    pub pinned: bool,
    pub trashed: bool,
}

impl Entry {
    /// Parse the public `otpauth://totp/` provisioning format. HOTP is unsupported.
    pub fn from_uri(uri: &str) -> Result<Self> {
        if uri.len() > MAX_ENTRY_BYTES {
            return Err(Error::InvalidEntry);
        }
        let parsed = Url::parse(uri).map_err(|_| Error::InvalidEntry)?;
        if parsed.scheme() != "otpauth"
            || parsed.host_str() != Some("totp")
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.port().is_some()
            || parsed.fragment().is_some()
        {
            return Err(Error::InvalidEntry);
        }
        let label = percent_decode_str(parsed.path().strip_prefix('/').ok_or(Error::InvalidEntry)?)
            .decode_utf8()
            .map_err(|_| Error::InvalidEntry)?;
        let label = label.trim();
        if label.is_empty() {
            return Err(Error::InvalidEntry);
        }
        let mut params = HashMap::new();
        for (name, value) in parsed.query_pairs() {
            if !matches!(
                name.as_ref(),
                "secret" | "issuer" | "algorithm" | "digits" | "period"
            ) || params
                .insert(name.into_owned(), Zeroizing::new(value.into_owned()))
                .is_some()
            {
                return Err(Error::InvalidEntry);
            }
        }
        let (label_issuer, account) = label.split_once(':').unwrap_or(("", label));
        let label_issuer = label_issuer.trim();
        let issuer = params
            .get("issuer")
            .map(|s| s.trim())
            .unwrap_or(label_issuer);
        if !label_issuer.is_empty() && !issuer.is_empty() && issuer != label_issuer {
            return Err(Error::InvalidEntry);
        }
        let entry = Self {
            name: label.to_owned(),
            account: account.trim().to_owned(),
            issuer: issuer.to_owned(),
            secret: canonical_secret(params.get("secret").ok_or(Error::InvalidEntry)?)?,
            algorithm: params
                .get("algorithm")
                .map(|s| s.to_ascii_uppercase())
                .unwrap_or("SHA1".into()),
            digits: params
                .get("digits")
                .map(|s| s.parse())
                .transpose()
                .map_err(|_| Error::InvalidEntry)?
                .unwrap_or(6),
            period: params
                .get("period")
                .map(|s| s.parse())
                .transpose()
                .map_err(|_| Error::InvalidEntry)?
                .unwrap_or(30),
            pinned: false,
            trashed: false,
        };
        entry.validate()?;
        Ok(entry)
    }

    pub fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty()
            || self.name.len() > 1024
            || self.account.len() > 1024
            || self.issuer.len() > 1024
            || !matches!(self.algorithm.as_str(), "SHA1" | "SHA256" | "SHA512")
            || !matches!(self.digits, 6 | 8)
            || !(1..=86_400).contains(&self.period)
        {
            return Err(Error::InvalidEntry);
        }
        decode_secret(&self.secret)?;
        Ok(())
    }

    /// RFC 6238 with T0=0, a 64-bit moving factor and RFC 4226 truncation.
    pub fn code_at(&self, timestamp: u64) -> Result<String> {
        self.validate()?;
        let secret = decode_secret(&self.secret)?;
        let counter = (timestamp / self.period).to_be_bytes();
        let digest = match self.algorithm.as_str() {
            "SHA1" => {
                let mut mac =
                    Hmac::<Sha1>::new_from_slice(&secret).map_err(|_| Error::InvalidEntry)?;
                mac.update(&counter);
                Zeroizing::new(mac.finalize().into_bytes().to_vec())
            }
            "SHA256" => {
                let mut mac =
                    Hmac::<Sha256>::new_from_slice(&secret).map_err(|_| Error::InvalidEntry)?;
                mac.update(&counter);
                Zeroizing::new(mac.finalize().into_bytes().to_vec())
            }
            "SHA512" => {
                let mut mac =
                    Hmac::<Sha512>::new_from_slice(&secret).map_err(|_| Error::InvalidEntry)?;
                mac.update(&counter);
                Zeroizing::new(mac.finalize().into_bytes().to_vec())
            }
            _ => return Err(Error::InvalidEntry),
        };
        let offset = usize::from(digest[digest.len() - 1] & 0x0f);
        let truncated = u32::from_be_bytes(
            digest[offset..offset + 4]
                .try_into()
                .map_err(|_| Error::InvalidEntry)?,
        ) & 0x7fff_ffff;
        let code = truncated % 10_u32.pow(self.digits);
        Ok(format!("{code:0width$}", width = self.digits as usize))
    }
}

pub fn encrypt_entry(
    key: &VaultKey,
    vault_id: Uuid,
    item_id: Uuid,
    entry: &Entry,
) -> Result<Sealed> {
    entry.validate()?;
    let bytes = Zeroizing::new(serde_json::to_vec(entry).map_err(|_| Error::InvalidEntry)?);
    if bytes.len() > MAX_ENTRY_BYTES {
        return Err(Error::InputTooLarge);
    }
    seal_raw(
        key.as_bytes(),
        &aad(vault_id, "entry", item_id.as_bytes())?,
        &bytes,
    )
}

pub fn decrypt_entry(
    key: &VaultKey,
    vault_id: Uuid,
    item_id: Uuid,
    sealed: &Sealed,
) -> Result<Entry> {
    let bytes = Zeroizing::new(open_raw(
        key.as_bytes(),
        &aad(vault_id, "entry", item_id.as_bytes())?,
        sealed,
        MAX_ENTRY_BYTES,
    )?);
    let entry: Entry = serde_json::from_slice(&bytes).map_err(|_| Error::InvalidEntry)?;
    entry.validate()?;
    Ok(entry)
}

fn canonical_secret(secret: &str) -> Result<String> {
    Ok(BASE32_NOPAD.encode(&decode_secret(secret)?))
}

fn decode_secret(secret: &str) -> Result<Zeroizing<Vec<u8>>> {
    if secret.len() > 2048 || !secret.is_ascii() {
        return Err(Error::InvalidEntry);
    }
    let upper = Zeroizing::new(secret.to_ascii_uppercase());
    let decoded = if upper.contains('=') {
        BASE32.decode(upper.as_bytes())
    } else {
        BASE32_NOPAD.decode(upper.as_bytes())
    }
    .map_err(|_| Error::InvalidEntry)?;
    let decoded = Zeroizing::new(decoded);
    // Accept existing authenticators down to 80 bits, without accepting empty or
    // trivially short secrets; issuers should generate at least 160 random bits.
    if !(10..=1024).contains(&decoded.len()) {
        return Err(Error::InvalidEntry);
    }
    Ok(decoded)
}
