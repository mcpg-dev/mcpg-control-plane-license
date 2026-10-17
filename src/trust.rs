//! The licence trust anchors: MCPG's licence issuer public keys, compiled in.
//!
//! A licence is accepted only when its header names (`kid`) one of these keys
//! and that key signed it. No key from configuration or the environment is a
//! trust anchor, so a self-signed licence verifies nowhere, and air-gapped
//! installs need no network to verify an MCPG-signed one.
//!
//! Every key carries a role and an environment. The role decides where what it
//! signs is accepted: a `self_host` key signs the licences a customer installs
//! (`mcpg-license issue`), a `cloud` key signs the ones the mcpg.cloud
//! federation hands to the platform, and a `platform` key signs no licence at
//! all, only the delivery proofs an mcpg.cloud control plane sends with each
//! licence ([`crate::delivery`]). A `staging` key admits only a licence that
//! marks `non_production`, so a leaked staging key cannot mint production
//! entitlements.
//!
//! Builds with debug assertions (tests, local development) also carry
//! [`test_override`], which trusts keys a test generates. Release builds are
//! compiled in the `opt` mode, which turns debug assertions off, so the override
//! does not exist there.

use std::sync::OnceLock;

use ed25519_dalek::VerifyingKey;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use sha2::{Digest, Sha256};

use crate::license::{LicenseClaims, LicenseError, MAX_SUPPORTED_LIC_VER};

/// The embedded key set; format and rules in the file's own header.
const ISSUER_KEYS: &str = include_str!("issuer_keys.txt");

/// The JOSE `typ` every licence carries, which keeps a licence from being
/// accepted where some other JWT from the same issuer is expected.
pub const LICENSE_JWT_TYP: &str = "mcpg-license+jwt";

/// Whether [`test_override`] is compiled into this build.
pub const TEST_TRUST_OVERRIDE_COMPILED_IN: bool = cfg!(debug_assertions);

/// Which licences a key signs, and so where they are accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IssuerRole {
    /// Self-host licences: a gateway's `license:` block, a control plane's
    /// offline licence.
    SelfHost,
    /// The licences the mcpg.cloud federation issues, which reach a gateway
    /// only through the platform.
    Cloud,
    /// No licence: the delivery proofs an mcpg.cloud control plane signs, so
    /// a gateway knows mcpg.cloud delivered the cloud licence it counts.
    Platform,
}

impl IssuerRole {
    pub fn as_str(self) -> &'static str {
        match self {
            IssuerRole::SelfHost => "self_host",
            IssuerRole::Cloud => "cloud",
            IssuerRole::Platform => "platform",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "self_host" => Some(IssuerRole::SelfHost),
            "cloud" => Some(IssuerRole::Cloud),
            "platform" => Some(IssuerRole::Platform),
            _ => None,
        }
    }
}

/// Whether a key may sign production licences.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KeyEnvironment {
    Production,
    /// Admits only a licence that marks `non_production`.
    Staging,
}

impl KeyEnvironment {
    pub fn as_str(self) -> &'static str {
        match self {
            KeyEnvironment::Production => "production",
            KeyEnvironment::Staging => "staging",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "production" => Some(KeyEnvironment::Production),
            "staging" => Some(KeyEnvironment::Staging),
            _ => None,
        }
    }
}

/// One trusted issuer key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuerKey {
    pub kid: String,
    pub role: IssuerRole,
    pub environment: KeyEnvironment,
    pub key: VerifyingKey,
}

/// A parsed key file: the keys in file order and the kids later revoked.
#[derive(Clone, Debug, Default)]
pub struct IssuerKeySet {
    keys: Vec<IssuerKey>,
    revoked: Vec<String>,
}

impl IssuerKeySet {
    /// Parse the key file format (see `issuer_keys.txt`). Every `kid` must be
    /// the thumbprint of its key, a kid appears in one `key` record, and a
    /// `revoke` names a key recorded above it.
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut set = IssuerKeySet::default();
        for (n, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let at = || format!("line {}", n + 1);
            let fields: Vec<&str> = line.split_whitespace().collect();
            match fields.as_slice() {
                ["key", kid, role, environment, x, added] => {
                    let role = IssuerRole::parse(role)
                        .ok_or_else(|| format!("{}: unknown role `{role}`", at()))?;
                    let environment = KeyEnvironment::parse(environment)
                        .ok_or_else(|| format!("{}: unknown environment `{environment}`", at()))?;
                    let key = public_key_from_b64url(x).map_err(|e| format!("{}: {e}", at()))?;
                    if thumbprint_kid(&key) != *kid {
                        return Err(format!(
                            "{}: kid `{kid}` is not the thumbprint of its key (expected `{}`)",
                            at(),
                            thumbprint_kid(&key)
                        ));
                    }
                    check_date(added).map_err(|e| format!("{}: {e}", at()))?;
                    if set.keys.iter().any(|k| k.kid == *kid) {
                        return Err(format!("{}: kid `{kid}` is recorded twice", at()));
                    }
                    set.keys.push(IssuerKey {
                        kid: (*kid).to_owned(),
                        role,
                        environment,
                        key,
                    });
                }
                ["revoke", kid, revoked_on] => {
                    check_date(revoked_on).map_err(|e| format!("{}: {e}", at()))?;
                    if !set.keys.iter().any(|k| k.kid == *kid) {
                        return Err(format!(
                            "{}: revokes `{kid}`, which no key record above names",
                            at()
                        ));
                    }
                    if set.revoked.iter().any(|r| r == kid) {
                        return Err(format!("{}: `{kid}` is revoked twice", at()));
                    }
                    set.revoked.push((*kid).to_owned());
                }
                _ => {
                    return Err(format!(
                        "{}: expected `key <kid> <role> <environment> <public-key> <added>` or \
                         `revoke <kid> <revoked-on>`",
                        at()
                    ));
                }
            }
        }
        Ok(set)
    }

    /// Every key recorded, revoked ones included, in file order.
    pub fn keys(&self) -> &[IssuerKey] {
        &self.keys
    }

    pub fn is_revoked(&self, kid: &str) -> bool {
        self.revoked.iter().any(|r| r == kid)
    }

    /// The key under `kid`, revoked or not.
    pub fn get(&self, kid: &str) -> Option<&IssuerKey> {
        self.keys.iter().find(|k| k.kid == kid)
    }
}

fn check_date(s: &str) -> Result<(), String> {
    chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d")
        .map(|_| ())
        .map_err(|_| format!("`{s}` is not a YYYY-MM-DD date"))
}

/// The key set compiled into this build.
pub fn embedded_issuer_keys() -> Result<&'static IssuerKeySet, LicenseError> {
    static PARSED: OnceLock<Result<IssuerKeySet, String>> = OnceLock::new();
    PARSED
        .get_or_init(|| IssuerKeySet::parse(ISSUER_KEYS))
        .as_ref()
        .map_err(|e| LicenseError::IssuerKeySet(e.clone()))
}

/// The trusted, unrevoked key under `kid`: the embedded set first, then (in
/// builds that carry it) the test override.
pub fn trusted_issuer_key(kid: &str) -> Result<IssuerKey, LicenseError> {
    trusted_key_in(embedded_issuer_keys()?, kid)
}

fn trusted_key_in(embedded: &IssuerKeySet, kid: &str) -> Result<IssuerKey, LicenseError> {
    if embedded.is_revoked(kid) {
        return Err(LicenseError::RevokedIssuerKey(kid.to_owned()));
    }
    if let Some(key) = embedded.get(kid) {
        return Ok(key.clone());
    }
    #[cfg(debug_assertions)]
    if let Some(key) = test_override::find(kid) {
        return Ok(key);
    }
    Err(LicenseError::UntrustedIssuerKey(kid.to_owned()))
}

/// The RFC 7638 JWK thumbprint of an Ed25519 key (SHA-256, base64url): the
/// `kid` a licence signed by it carries.
pub fn thumbprint_kid(key: &VerifyingKey) -> String {
    // RFC 7638 §3.2: the required members in lexicographic order, no whitespace.
    let canonical = format!(
        r#"{{"crv":"Ed25519","kty":"OKP","x":"{}"}}"#,
        public_key_b64url(key)
    );
    b64url_encode(&Sha256::digest(canonical.as_bytes()))
}

/// The raw public key, base64url without padding (the JWK `x` member).
pub fn public_key_b64url(key: &VerifyingKey) -> String {
    b64url_encode(key.as_bytes())
}

/// Parse the JWK `x` form of an Ed25519 public key. Only the canonical
/// encoding is accepted, so one key has one spelling in the key file.
pub fn public_key_from_b64url(x: &str) -> Result<VerifyingKey, String> {
    let bytes =
        b64url_decode(x).ok_or_else(|| format!("`{x}` is not base64url without padding"))?;
    let raw: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("public key is {} bytes, not 32", bytes.len()))?;
    VerifyingKey::from_bytes(&raw).map_err(|e| format!("not an Ed25519 public key: {e}"))
}

/// The key-file record for a key, dated `added` (YYYY-MM-DD).
pub fn key_record(
    role: IssuerRole,
    environment: KeyEnvironment,
    key: &VerifyingKey,
    added: &str,
) -> String {
    format!(
        "key {} {} {} {} {added}",
        thumbprint_kid(key),
        role.as_str(),
        environment.as_str(),
        public_key_b64url(key)
    )
}

/// Where a licence is being presented: the audience it must name, the key
/// roles accepted there, and whether an expired licence is refused outright or
/// returned for the caller's grace policy to judge.
#[derive(Clone, Copy, Debug)]
pub struct TrustPolicy<'a> {
    pub audience: &'a str,
    pub roles: &'a [IssuerRole],
    pub enforce_expiry: bool,
}

/// A licence that verified under a trusted issuer key.
#[derive(Clone, Debug)]
pub struct VendorLicense {
    pub claims: LicenseClaims,
    pub kid: String,
    pub role: IssuerRole,
    pub environment: KeyEnvironment,
}

/// Verify `token` against the trusted issuer keys.
///
/// Checks, in order: `alg` EdDSA and `typ` [`LICENSE_JWT_TYP`]; a `kid` that
/// names a trusted, unrevoked key; a key role the policy accepts; the
/// signature, the audience, `nbf` and (when the policy enforces it) `exp`,
/// with 60 seconds of leeway; `lic_ver`; and, for a staging key, that the
/// licence marks `non_production`.
pub fn verify_vendor_license(
    token: &str,
    policy: &TrustPolicy<'_>,
) -> Result<VendorLicense, LicenseError> {
    verify_in(embedded_issuer_keys()?, token, policy)
}

fn verify_in(
    embedded: &IssuerKeySet,
    token: &str,
    policy: &TrustPolicy<'_>,
) -> Result<VendorLicense, LicenseError> {
    let header = jsonwebtoken::decode_header(token)
        .map_err(|e| LicenseError::Verification(format!("malformed licence header: {e}")))?;
    if header.alg != Algorithm::EdDSA {
        return Err(LicenseError::Verification(format!(
            "licence algorithm {:?} is not EdDSA",
            header.alg
        )));
    }
    if header.typ.as_deref() != Some(LICENSE_JWT_TYP) {
        return Err(LicenseError::Verification(format!(
            "licence header typ is {:?}, not `{LICENSE_JWT_TYP}`",
            header.typ.as_deref().unwrap_or("")
        )));
    }
    let kid = header
        .kid
        .ok_or_else(|| LicenseError::UntrustedIssuerKey("(no kid)".to_owned()))?;
    let issuer = trusted_key_in(embedded, &kid)?;
    if !policy.roles.contains(&issuer.role) {
        return Err(LicenseError::IssuerRoleNotAccepted {
            kid,
            role: issuer.role.as_str(),
        });
    }

    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_audience(&[policy.audience]);
    validation.validate_nbf = true;
    validation.validate_exp = policy.enforce_expiry;
    validation.leeway = 60;
    let key = DecodingKey::from_ed_der(issuer.key.to_bytes().as_ref());
    let claims = jsonwebtoken::decode::<LicenseClaims>(token, &key, &validation)
        .map_err(|e| LicenseError::Verification(e.to_string()))?
        .claims;
    if claims.lic_ver > MAX_SUPPORTED_LIC_VER {
        return Err(LicenseError::UnsupportedVersion(claims.lic_ver));
    }
    if issuer.environment == KeyEnvironment::Staging && !claims.non_production {
        return Err(LicenseError::StagingKeyProductionLicense(kid));
    }
    Ok(VendorLicense {
        claims,
        kid,
        role: issuer.role,
        environment: issuer.environment,
    })
}

const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

pub(crate) fn b64url_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, b)| acc | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..=chunk.len() {
            out.push(B64URL[((n >> (18 - 6 * i)) & 0x3f) as usize] as char);
        }
    }
    out
}

fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    for chunk in s.as_bytes().chunks(4) {
        let mut n = 0u32;
        for (i, c) in chunk.iter().enumerate() {
            let v = B64URL.iter().position(|a| a == c)? as u32;
            n |= v << (18 - 6 * i);
        }
        for i in 0..chunk.len() - 1 {
            out.push((n >> (16 - 8 * i)) as u8);
        }
    }
    // One key, one spelling: stray low bits would give a second encoding.
    (b64url_encode(&out) == s).then_some(out)
}

/// Keys a test trusts in addition to the embedded set. Compiled only with
/// debug assertions, so it is absent from release builds.
#[cfg(debug_assertions)]
pub mod test_override {
    use std::sync::{OnceLock, RwLock};

    use ed25519_dalek::SigningKey;
    use ed25519_dalek::pkcs8::EncodePrivateKey;
    use jsonwebtoken::{EncodingKey, Header};

    use super::*;

    /// Extra key records (the key-file `key` form, separated by `;` or new
    /// lines) for a test that runs a separate process.
    pub const ENV: &str = "MCPG_LICENSE_TEST_ISSUER_KEYS";

    static TRUSTED: RwLock<Vec<IssuerKey>> = RwLock::new(Vec::new());

    fn from_env() -> &'static [IssuerKey] {
        static PARSED: OnceLock<Vec<IssuerKey>> = OnceLock::new();
        PARSED.get_or_init(|| {
            std::env::var(ENV)
                .ok()
                .and_then(|raw| IssuerKeySet::parse(&raw.replace(';', "\n")).ok())
                .map(|set| set.keys().to_vec())
                .unwrap_or_default()
        })
    }

    pub(super) fn find(kid: &str) -> Option<IssuerKey> {
        if let Some(key) = from_env().iter().find(|k| k.kid == kid) {
            return Some(key.clone());
        }
        TRUSTED
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .find(|k| k.kid == kid)
            .cloned()
    }

    /// Trust `key` in this process under `role` and `environment`; returns
    /// its kid.
    pub fn trust_issuer_key(
        role: IssuerRole,
        environment: KeyEnvironment,
        key: &VerifyingKey,
    ) -> String {
        let kid = thumbprint_kid(key);
        let mut trusted = TRUSTED.write().unwrap_or_else(|e| e.into_inner());
        if !trusted.iter().any(|k| k.kid == kid) {
            trusted.push(IssuerKey {
                kid: kid.clone(),
                role,
                environment,
                key: *key,
            });
        }
        kid
    }

    /// Sign `claims` as a licence with `key`: the header carries the key's
    /// thumbprint as `kid` and [`LICENSE_JWT_TYP`].
    pub fn sign(claims: &LicenseClaims, key: &SigningKey) -> String {
        let der = key.to_pkcs8_der().expect("encode an Ed25519 key as PKCS#8");
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(thumbprint_kid(&key.verifying_key()));
        header.typ = Some(LICENSE_JWT_TYP.to_owned());
        jsonwebtoken::encode(&header, claims, &EncodingKey::from_ed_der(der.as_bytes()))
            .expect("sign a licence")
    }

    /// A fresh key, trusted under `role` and `environment`.
    pub fn trusted_signing_key(role: IssuerRole, environment: KeyEnvironment) -> SigningKey {
        let key = SigningKey::generate(&mut rand::rng());
        trust_issuer_key(role, environment, &key.verifying_key());
        key
    }

    /// `claims` signed by a fresh key trusted under `role` and `environment`.
    pub fn issue(role: IssuerRole, environment: KeyEnvironment, claims: &LicenseClaims) -> String {
        sign(claims, &trusted_signing_key(role, environment))
    }
}

#[cfg(all(test, debug_assertions))]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::test_override::{issue, sign, trusted_signing_key};
    use super::*;
    use crate::license::{AUDIENCE_CP, AUDIENCE_GATEWAY, AUDIENCE_GATEWAY_MANAGED};

    /// Every record the key file has ever held, in order: the file's own
    /// records must be exactly these. A new key or revocation is appended to
    /// the file AND here in the same change; nothing in either list is ever
    /// edited or removed, because an older release ships every one of them.
    const PUBLISHED_RECORDS: &[&str] = &[
        "key Wej9_GT1ntIXp_mx9X2I2wtppquI-OWfxYNl5wC2e4k self_host production lzekbDEdypRSSZOXX3kDRcLLYfTsRkcnRTXBubo8uZ4 2026-10-12",
        "key 3f96x_zTmaJw2kvm2wzHZIe0fVeKdCvGx2XgAm7DyPY self_host production 34OBdUxtUUQw-ylXE8ZzJJ3jYoL9pxH4Km1O3Ucc764 2026-10-12",
        "key JDTuYyleXAFTmZywEvcdXRzC_zWlkrdbOlZnOPsVqhU self_host staging MUIK9SAzoP1paUc8jm7F_IGt9p79acxgLPAeI0Ih1e4 2026-10-12",
        "key AH931Z9OQWJnM9sLjeYCSQ0Eb9hwlA7skdRDzS5N0ag cloud production F8MFBLI_isQxXI534ELZGR_bCewUoOKHP-yO5soSZkU 2026-10-12",
        "key oyMfEC1Li5G3LCsYxSOQbdgHvhdHNuaUoCdiFmljE6I cloud production z4aw3ajhu7I-FR0YCYsimQLGknDd4pI5KbZCoO_igdY 2026-10-12",
        "key gWQ2toZKLYg1IE99ogkw0s9QNhiimgbcqLnYPqZwqM0 cloud staging U3NelpNPse5D2HfQm-eTiCUxJKVSllPAG5dStkDHIY8 2026-10-12",
        "key AsvhOhHiTr_Cepn7lrBCB7P3ucoK2cnXuX93TrVW_YU platform production fEybRy5QEmFg7Sz_CeaGacC7uPKrmqhyiutZQk3HvYU 2026-10-12",
        "key ADWgMkV9h1r-uwO21eWa4qKMfzFtLsHOXXUb2Jqsvdg platform production V0FyqQrhrMwd1pqhtfBaHoRR2W5B9EK4jeiZ0taoNxI 2026-10-12",
        "key ay2Ux7Js3_s6ZY1zhDG8UXVpKQauvOiWG_yZy7cCtQc platform staging awe2ryg0leDVWz9Dv_KpBVJLDIA2rCocblKiXjdWqyI 2026-10-12",
    ];

    fn records(text: &str) -> Vec<String> {
        text.lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(|l| l.split_whitespace().collect::<Vec<_>>().join(" "))
            .collect()
    }

    #[test]
    fn the_key_file_is_append_only() {
        let set = IssuerKeySet::parse(ISSUER_KEYS).expect("the embedded key file parses");
        let in_file = records(ISSUER_KEYS);
        let published: Vec<String> = PUBLISHED_RECORDS.iter().map(|r| (*r).to_owned()).collect();
        for (i, record) in published.iter().enumerate() {
            assert_eq!(
                in_file.get(i),
                Some(record),
                "published record {i} was edited or removed; the key file is append-only"
            );
        }
        assert_eq!(
            in_file.len(),
            published.len(),
            "a record was appended to issuer_keys.txt without being appended to \
             PUBLISHED_RECORDS: {:?}",
            &in_file[published.len().min(in_file.len())..]
        );
        assert_eq!(
            set.keys().len() + set.revoked.len(),
            in_file.len(),
            "every record is a key or a revocation"
        );
    }

    fn claims(aud: &[&str]) -> LicenseClaims {
        let mut c = LicenseClaims::community(aud[0]);
        c.aud = aud.iter().map(|a| (*a).to_owned()).collect();
        c.iss = "https://license.test".into();
        c.plan = "team".into();
        c.exp = chrono::Utc::now().timestamp() + 3_600;
        c.nbf = chrono::Utc::now().timestamp();
        c
    }

    const SELF_HOST_GATEWAY: TrustPolicy<'static> = TrustPolicy {
        audience: AUDIENCE_GATEWAY,
        roles: &[IssuerRole::SelfHost],
        enforce_expiry: true,
    };

    #[test]
    fn a_trusted_key_verifies_and_reports_itself() {
        let key = trusted_signing_key(IssuerRole::SelfHost, KeyEnvironment::Production);
        let token = sign(&claims(&[AUDIENCE_CP, AUDIENCE_GATEWAY]), &key);
        let verified = verify_vendor_license(&token, &SELF_HOST_GATEWAY).unwrap();
        assert_eq!(verified.claims.plan, "team");
        assert_eq!(verified.kid, thumbprint_kid(&key.verifying_key()));
        assert_eq!(verified.role, IssuerRole::SelfHost);
        assert_eq!(verified.environment, KeyEnvironment::Production);
    }

    /// The failure this whole module exists for: a key nobody at MCPG holds.
    #[test]
    fn a_key_outside_the_trusted_set_is_refused() {
        let stranger = SigningKey::generate(&mut rand::rng());
        let token = sign(&claims(&[AUDIENCE_GATEWAY]), &stranger);
        let err = verify_vendor_license(&token, &SELF_HOST_GATEWAY).unwrap_err();
        assert!(
            matches!(&err, LicenseError::UntrustedIssuerKey(kid) if *kid == thumbprint_kid(&stranger.verifying_key())),
            "{err}"
        );
    }

    #[test]
    fn a_key_of_another_role_is_refused() {
        let token = issue(
            IssuerRole::Cloud,
            KeyEnvironment::Production,
            &claims(&[AUDIENCE_GATEWAY]),
        );
        let err = verify_vendor_license(&token, &SELF_HOST_GATEWAY).unwrap_err();
        assert!(
            matches!(
                err,
                LicenseError::IssuerRoleNotAccepted { role: "cloud", .. }
            ),
            "{err}"
        );
    }

    #[test]
    fn the_audience_must_match() {
        let token = issue(
            IssuerRole::SelfHost,
            KeyEnvironment::Production,
            &claims(&[AUDIENCE_CP, AUDIENCE_GATEWAY_MANAGED]),
        );
        assert!(verify_vendor_license(&token, &SELF_HOST_GATEWAY).is_err());
    }

    /// A leaked staging key cannot mint a production licence.
    #[test]
    fn a_staging_key_admits_only_a_non_production_licence() {
        let key = trusted_signing_key(IssuerRole::SelfHost, KeyEnvironment::Staging);
        let production = sign(&claims(&[AUDIENCE_GATEWAY]), &key);
        let err = verify_vendor_license(&production, &SELF_HOST_GATEWAY).unwrap_err();
        assert!(
            matches!(err, LicenseError::StagingKeyProductionLicense(_)),
            "{err}"
        );

        let mut marked = claims(&[AUDIENCE_GATEWAY]);
        marked.non_production = true;
        let verified =
            verify_vendor_license(&sign(&marked, &key), &SELF_HOST_GATEWAY).expect("marked");
        assert!(verified.claims.non_production);
        assert_eq!(verified.environment, KeyEnvironment::Staging);
    }

    #[test]
    fn a_production_key_admits_a_non_production_licence_too() {
        let mut marked = claims(&[AUDIENCE_GATEWAY]);
        marked.non_production = true;
        let token = issue(IssuerRole::SelfHost, KeyEnvironment::Production, &marked);
        assert!(verify_vendor_license(&token, &SELF_HOST_GATEWAY).is_ok());
    }

    #[test]
    fn expiry_is_refused_or_left_to_the_caller() {
        let mut expired = claims(&[AUDIENCE_GATEWAY]);
        expired.exp = chrono::Utc::now().timestamp() - 3_600;
        let token = issue(IssuerRole::SelfHost, KeyEnvironment::Production, &expired);
        assert!(verify_vendor_license(&token, &SELF_HOST_GATEWAY).is_err());
        let lenient = TrustPolicy {
            enforce_expiry: false,
            ..SELF_HOST_GATEWAY
        };
        let verified = verify_vendor_license(&token, &lenient).expect("signature still good");
        assert_eq!(verified.claims.exp, expired.exp);
    }

    #[test]
    fn a_licence_without_the_licence_typ_is_refused() {
        use ed25519_dalek::pkcs8::EncodePrivateKey;
        let key = trusted_signing_key(IssuerRole::SelfHost, KeyEnvironment::Production);
        let mut header = jsonwebtoken::Header::new(Algorithm::EdDSA);
        header.kid = Some(thumbprint_kid(&key.verifying_key()));
        let der = key.to_pkcs8_der().unwrap();
        let token = jsonwebtoken::encode(
            &header,
            &claims(&[AUDIENCE_GATEWAY]),
            &jsonwebtoken::EncodingKey::from_ed_der(der.as_bytes()),
        )
        .unwrap();
        let err = verify_vendor_license(&token, &SELF_HOST_GATEWAY).unwrap_err();
        assert!(err.to_string().contains(LICENSE_JWT_TYP), "{err}");
    }

    #[test]
    fn a_tampered_licence_is_refused() {
        let token = issue(
            IssuerRole::SelfHost,
            KeyEnvironment::Production,
            &claims(&[AUDIENCE_GATEWAY]),
        );
        let mut parts: Vec<String> = token.split('.').map(str::to_owned).collect();
        let mut payload: LicenseClaims = serde_json::from_slice(&b64url_decode(&parts[1]).unwrap())
            .expect("payload is the claims");
        payload.plan = "enterprise".into();
        parts[1] = b64url_encode(&serde_json::to_vec(&payload).unwrap());
        let err = verify_vendor_license(&parts.join("."), &SELF_HOST_GATEWAY).unwrap_err();
        assert!(matches!(err, LicenseError::Verification(_)), "{err}");
    }

    fn record(role: &str, environment: &str, key: &VerifyingKey) -> String {
        format!(
            "key {} {role} {environment} {} 2026-10-01",
            thumbprint_kid(key),
            public_key_b64url(key)
        )
    }

    #[test]
    fn the_parser_holds_every_record_to_its_rules() {
        let a = SigningKey::generate(&mut rand::rng()).verifying_key();
        let b = SigningKey::generate(&mut rand::rng()).verifying_key();
        let good = format!(
            "# comment\n\n{}\n{}\nrevoke {} 2026-11-01\n",
            record("self_host", "production", &a),
            record("cloud", "staging", &b),
            thumbprint_kid(&a)
        );
        let set = IssuerKeySet::parse(&good).unwrap();
        assert_eq!(set.keys().len(), 2);
        assert!(set.is_revoked(&thumbprint_kid(&a)));
        assert!(!set.is_revoked(&thumbprint_kid(&b)));
        assert_eq!(set.keys()[1].role, IssuerRole::Cloud);
        assert_eq!(set.keys()[1].environment, KeyEnvironment::Staging);
        assert_eq!(
            key_record(
                IssuerRole::SelfHost,
                KeyEnvironment::Production,
                &a,
                "2026-10-01"
            ),
            record("self_host", "production", &a)
        );

        let cases: Vec<(String, &str)> = vec![
            (
                format!(
                    "key {} self_host production {} 2026-10-01",
                    thumbprint_kid(&b),
                    public_key_b64url(&a)
                ),
                "thumbprint",
            ),
            (record("self_hosted", "production", &a), "unknown role"),
            (record("cloud", "prod", &a), "unknown environment"),
            (
                format!(
                    "{}\n{}",
                    record("cloud", "staging", &a),
                    record("cloud", "staging", &a)
                ),
                "twice",
            ),
            (
                format!("revoke {} 2026-10-01", thumbprint_kid(&a)),
                "no key record",
            ),
            (
                record("cloud", "staging", &a).replace("2026-10-01", "01-10-2026"),
                "YYYY-MM-DD",
            ),
            ("key a b".to_owned(), "expected"),
        ];
        for (bad, why) in cases {
            let err = IssuerKeySet::parse(&bad).unwrap_err();
            assert!(err.contains(why), "{bad}: {err}");
        }
    }

    /// A platform key is recorded like the others, and signs no licence: it
    /// is accepted only where a policy names its role, and no licence policy
    /// does.
    #[test]
    fn a_platform_key_is_recorded_and_verifies_no_licence() {
        let key = SigningKey::generate(&mut rand::rng());
        let set = IssuerKeySet::parse(&record("platform", "staging", &key.verifying_key()))
            .expect("a platform record parses");
        assert_eq!(set.keys()[0].role, IssuerRole::Platform);
        assert_eq!(IssuerRole::Platform.as_str(), "platform");
        assert_eq!(IssuerRole::parse("platform"), Some(IssuerRole::Platform));

        let platform = trusted_signing_key(IssuerRole::Platform, KeyEnvironment::Production);
        let token = sign(&claims(&[AUDIENCE_GATEWAY]), &platform);
        let err = verify_vendor_license(&token, &SELF_HOST_GATEWAY).unwrap_err();
        assert!(
            matches!(
                err,
                LicenseError::IssuerRoleNotAccepted {
                    role: "platform",
                    ..
                }
            ),
            "{err}"
        );
    }

    /// A revocation reaches every token the key ever signed, whatever it
    /// claims about itself.
    #[test]
    fn a_revoked_key_verifies_nothing() {
        let key = SigningKey::generate(&mut rand::rng());
        let kid = thumbprint_kid(&key.verifying_key());
        let listed =
            IssuerKeySet::parse(&record("self_host", "production", &key.verifying_key())).unwrap();
        let token = sign(&claims(&[AUDIENCE_GATEWAY]), &key);
        verify_in(&listed, &token, &SELF_HOST_GATEWAY).expect("listed and not revoked");

        let revoked = IssuerKeySet::parse(&format!(
            "{}\nrevoke {kid} 2026-11-01\n",
            record("self_host", "production", &key.verifying_key())
        ))
        .unwrap();
        let err = verify_in(&revoked, &token, &SELF_HOST_GATEWAY).unwrap_err();
        assert!(
            matches!(&err, LicenseError::RevokedIssuerKey(k) if *k == kid),
            "{err}"
        );
    }

    /// tools/ci/verify-artifact.py refuses a release artefact that contains
    /// this name, so the name and the check move together.
    #[test]
    fn the_override_variable_is_the_release_marker() {
        assert_eq!(super::test_override::ENV, "MCPG_LICENSE_TEST_ISSUER_KEYS");
    }

    #[test]
    fn base64url_round_trips_and_has_one_spelling() {
        for len in 0..40 {
            let bytes: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            let s = b64url_encode(&bytes);
            assert!(!s.contains('='));
            assert_eq!(
                b64url_decode(&s).as_deref(),
                Some(bytes.as_slice()),
                "{len}"
            );
        }
        // `B` carries a stray low bit that `A` does not.
        assert_eq!(b64url_decode("AA"), Some(vec![0]));
        assert_eq!(b64url_decode("AB"), None);
        assert_eq!(b64url_decode("A"), None);
        assert_eq!(b64url_decode("A+"), None);
    }

    /// RFC 7638 §3.1's worked example is RSA; this pins the Ed25519 form
    /// against RFC 8037 appendix A.3, which gives the thumbprint of its
    /// example key.
    #[test]
    fn the_thumbprint_is_rfc_8037s() {
        let key = public_key_from_b64url("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo").unwrap();
        assert_eq!(
            thumbprint_kid(&key),
            "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
        );
    }
}
