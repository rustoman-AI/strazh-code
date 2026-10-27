//! Strazh Pro licensing — a simple, offline, local-only gate (v1).
//!
//! ## What this is
//! A license key is a tiny signed token (JWT-like) the app validates **locally**,
//! with no server and no network call. Format:
//!
//! ```text
//! SZ1-<base64url(payload_json)>.<base64url(hmac_sha256(payload_segment))>
//! ```
//!
//! `payload_json` is `{"name": "...", "plan": "pro", "exp": <unix_secs | 0>}`.
//! `exp == 0` means a perpetual key. The signature is HMAC-SHA256 over the
//! **payload segment string** (the base64url text, not the raw JSON) using a
//! secret embedded in the binary.
//!
//! ## Honest security note (read me)
//! This is a *good-faith* gate, not copy protection. The HMAC secret ships
//! inside the desktop binary, so a determined user can extract it and mint keys.
//! That is an accepted trade-off for v1: it keeps honest users honest without a
//! server, accounts, or telemetry. If/when a licensing server is introduced,
//! move signing server-side and keep only a *public* verification key here.
//!
//! No new crates: HMAC and base64url are built on the `sha2` crate that the
//! project already depends on.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// v1 HMAC secret for signing/verifying license keys.
///
/// ⚠️ LOCAL-ONLY GATE: this secret is embedded in the shipped binary and is
/// therefore extractable. To rotate it, change this value and re-issue keys
/// (old keys stop validating). Keep it out of logs and UI.
const LICENSE_SECRET: &[u8] = b"strazh.pro.v1.4b1c9f2e-DO-NOT-LOG-rotate-to-invalidate";

/// Token version prefix. Bump if the payload shape changes.
const PREFIX: &str = "SZ1-";

/// The decoded license payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicensePayload {
    /// Who the key was issued to (name/email/order id). Informational only.
    #[serde(default)]
    pub name: String,
    /// Plan identifier. Only "pro" unlocks paid features today.
    pub plan: String,
    /// Expiry as a Unix timestamp (seconds). `0` == perpetual.
    #[serde(default)]
    pub exp: u64,
}

/// Result of checking the currently stored key — shaped for the UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseStatus {
    /// True when a valid, non-expired Pro key is stored.
    pub pro: bool,
    /// "none" | "pro" | "invalid" | "expired"
    pub plan: String,
    /// Name the key was issued to (empty when not licensed).
    pub name: String,
    /// Expiry Unix seconds (0 = perpetual, omitted when not licensed).
    pub exp: u64,
    /// Human-readable message for the UI.
    pub message: String,
}

impl LicenseStatus {
    fn free(message: &str) -> Self {
        LicenseStatus {
            pro: false,
            plan: "none".into(),
            name: String::new(),
            exp: 0,
            message: message.into(),
        }
    }
}

// ── base64url (no padding) — minimal, dependency-free ──────────────────────

const B64URL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn b64url_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity((input.len() * 4 + 2) / 3);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64URL[((n >> 18) & 63) as usize] as char);
        out.push(B64URL[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(B64URL[((n >> 6) & 63) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(B64URL[(n & 63) as usize] as char);
        }
    }
    out
}

fn b64url_decode(input: &str) -> Option<Vec<u8>> {
    let mut vals = Vec::with_capacity(input.len());
    for c in input.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        };
        vals.push(v);
    }
    let mut out = Vec::with_capacity(vals.len() * 3 / 4);
    for chunk in vals.chunks(4) {
        let n = (chunk[0] as u32) << 18
            | (*chunk.get(1).unwrap_or(&0) as u32) << 12
            | (*chunk.get(2).unwrap_or(&0) as u32) << 6
            | (*chunk.get(3).unwrap_or(&0) as u32);
        out.push((n >> 16) as u8);
        if chunk.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(n as u8);
        }
    }
    Some(out)
}

// ── HMAC-SHA256 (RFC 2104) on top of the sha2 crate ────────────────────────

fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    // Normalize the key to one block.
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        let digest = Sha256::digest(key);
        k[..32].copy_from_slice(&digest);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(msg);
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_digest);
    let out = outer.finalize();
    let mut res = [0u8; 32];
    res.copy_from_slice(&out);
    res
}

/// Constant-time byte comparison (avoids leaking match length via timing).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Sign a payload into a license key string. Used by the keygen binary.
pub fn sign(payload: &LicensePayload) -> String {
    let json = serde_json::to_vec(payload).expect("payload serializes");
    let payload_seg = b64url_encode(&json);
    let sig = hmac_sha256(LICENSE_SECRET, payload_seg.as_bytes());
    let sig_seg = b64url_encode(&sig);
    format!("{PREFIX}{payload_seg}.{sig_seg}")
}

/// Validate a key string (format + signature + expiry). Returns the decoded
/// payload on success. Never panics on malformed input.
pub fn validate(key: &str) -> Result<LicensePayload, String> {
    let key = key.trim();
    let body = key
        .strip_prefix(PREFIX)
        .ok_or_else(|| "Not a Strazh license key.".to_string())?;
    let (payload_seg, sig_seg) = body
        .split_once('.')
        .ok_or_else(|| "Malformed license key.".to_string())?;

    // Recompute and compare the signature in constant time.
    let expected = hmac_sha256(LICENSE_SECRET, payload_seg.as_bytes());
    let got = b64url_decode(sig_seg).ok_or_else(|| "Malformed signature.".to_string())?;
    if !ct_eq(&expected, &got) {
        return Err("License signature does not match.".into());
    }

    let json = b64url_decode(payload_seg).ok_or_else(|| "Malformed payload.".to_string())?;
    let payload: LicensePayload =
        serde_json::from_slice(&json).map_err(|_| "Unreadable license payload.".to_string())?;

    if payload.exp != 0 && now_unix() > payload.exp {
        return Err("License has expired.".into());
    }
    Ok(payload)
}

/// Turn a (possibly empty) stored key into a UI-facing status.
pub fn status_from_key(stored: Option<String>) -> LicenseStatus {
    let Some(key) = stored.filter(|k| !k.trim().is_empty()) else {
        return LicenseStatus::free("Free plan. Upgrade to Pro to apply fixes.");
    };
    match validate(&key) {
        Ok(p) if p.plan == "pro" => LicenseStatus {
            pro: true,
            plan: "pro".into(),
            name: p.name.clone(),
            exp: p.exp,
            message: if p.exp == 0 {
                "Strazh Pro — active.".into()
            } else {
                "Strazh Pro — active (subscription).".into()
            },
        },
        Ok(_) => LicenseStatus::free("Key is valid but not a Pro plan."),
        Err(e) => {
            let mut s = LicenseStatus::free(&e);
            s.plan = if e.contains("expired") { "expired".into() } else { "invalid".into() };
            s
        }
    }
}

// ── Persistence: one documented file in the per-user config dir ────────────

/// The license key file path:
///   Windows: %APPDATA%\com.strazh.app\license.key
///   macOS:   ~/Library/Application Support/com.strazh.app/license.key
///   Linux:   $XDG_CONFIG_HOME/com.strazh.app/license.key (or ~/.config/...)
/// Mirrors the credential path logic in `lib.rs` (same app identifier/dir).
pub fn license_path_from(get: &dyn Fn(&str) -> Option<String>) -> Option<std::path::PathBuf> {
    const APP_IDENTIFIER: &str = "com.strazh.app";
    let base: std::path::PathBuf = if cfg!(windows) {
        get("APPDATA").map(std::path::PathBuf::from)?
    } else if cfg!(target_os = "macos") {
        let home = get("HOME")?;
        std::path::Path::new(&home).join("Library").join("Application Support")
    } else {
        match get("XDG_CONFIG_HOME") {
            Some(x) if !x.is_empty() => std::path::PathBuf::from(x),
            _ => std::path::Path::new(&get("HOME")?).join(".config"),
        }
    };
    Some(base.join(APP_IDENTIFIER).join("license.key"))
}

fn license_path() -> Option<std::path::PathBuf> {
    license_path_from(&|k| std::env::var(k).ok())
}

/// Read the stored key (if any) from disk.
pub fn read_stored() -> Option<String> {
    let path = license_path()?;
    std::fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

/// Persist a validated key to disk. Creates the config dir if needed.
pub fn write_stored(key: &str) -> Result<(), String> {
    let path = license_path().ok_or_else(|| "Cannot resolve config directory.".to_string())?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("Cannot create config dir: {e}"))?;
    }
    std::fs::write(&path, key.trim()).map_err(|e| format!("Cannot write license file: {e}"))
}

/// Remove the stored key (revert to Free).
pub fn remove_stored() -> Result<(), String> {
    if let Some(path) = license_path() {
        if path.exists() {
            std::fs::remove_file(&path).map_err(|e| format!("Cannot remove license file: {e}"))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(name: &str, plan: &str, exp: u64) -> String {
        sign(&LicensePayload { name: name.into(), plan: plan.into(), exp })
    }

    #[test]
    fn roundtrip_b64url() {
        for sample in [&b""[..], b"a", b"ab", b"abc", b"abcd", b"\x00\xff\x10hello"] {
            let enc = b64url_encode(sample);
            assert_eq!(b64url_decode(&enc).unwrap(), sample.to_vec());
        }
    }

    #[test]
    fn valid_perpetual_pro_key_unlocks() {
        let k = key("Ada", "pro", 0);
        let s = status_from_key(Some(k));
        assert!(s.pro);
        assert_eq!(s.plan, "pro");
        assert_eq!(s.name, "Ada");
    }

    #[test]
    fn tampered_payload_fails() {
        let k = key("Ada", "pro", 0);
        // Flip a character in the payload segment.
        let body = k.strip_prefix(PREFIX).unwrap();
        let (p, sig) = body.split_once('.').unwrap();
        let mut p2: Vec<char> = p.chars().collect();
        p2[0] = if p2[0] == 'A' { 'B' } else { 'A' };
        let tampered = format!("{PREFIX}{}.{}", p2.into_iter().collect::<String>(), sig);
        assert!(validate(&tampered).is_err());
    }

    #[test]
    fn expired_key_is_rejected() {
        let k = key("Past", "pro", 1); // Jan 1 1970 + 1s
        let s = status_from_key(Some(k));
        assert!(!s.pro);
        assert_eq!(s.plan, "expired");
    }

    #[test]
    fn free_plan_key_does_not_unlock() {
        let k = key("Trial", "free", 0);
        let s = status_from_key(Some(k));
        assert!(!s.pro);
    }

    #[test]
    fn garbage_is_rejected() {
        assert!(!status_from_key(Some("not-a-key".into())).pro);
        assert!(!status_from_key(Some("SZ1-xxx.yyy".into())).pro);
        assert!(!status_from_key(None).pro);
    }
}
