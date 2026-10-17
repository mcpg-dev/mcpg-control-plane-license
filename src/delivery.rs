//! Proof that mcpg.cloud itself delivered a licence to a gateway.
//!
//! A cloud licence reaches a gateway only through the platform, but the
//! licence alone does not say which control plane relayed it: a customer's own
//! control plane could relay a copy. So every Channel a gateway opens carries
//! a fresh random nonce ([`DELIVERY_NONCE_HEADER`]), and an mcpg.cloud control
//! plane sends each licence with a delivery proof: a short-lived JWT it signs
//! with its `platform` issuer key over the org, the licence's digest, that
//! nonce and the instance uid the Channel is authenticated as. The gateway
//! verifies it against the `platform` keys compiled into it. Only mcpg.cloud's
//! control planes hold a platform key, so a control plane without one, such
//! as a customer's own, cannot make a cloud licence count; a copied licence,
//! or a proof replayed onto another Channel or another instance, proves
//! nothing. A proof does not show that no other control plane stands in
//! between: the gateway takes the instance uid from its own instance token,
//! which the control plane it enrolled with issued, so one that holds a real
//! hybrid enrollment can pass that enrollment's Channel, and its proofs, to
//! several gateways in turns.
//!
//! A platform key signs no licence, and a proof carries its own `typ` and
//! audience, so neither token is ever accepted as the other.
//!
//! A gateway keeps the last proof it verified with the delivery it cached. A
//! restart counts that cached licence for [`LAST_KNOWN_GOOD_SECS`] after the
//! proof was signed ([`verify_cached_delivery_proof`]), while it waits for its
//! control plane.

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::license::LicenseError;
use crate::trust::{IssuerRole, KeyEnvironment, b64url_encode, trusted_issuer_key};

/// The JOSE `typ` of a delivery proof.
pub const DELIVERY_PROOF_TYP: &str = "mcpg-delivery+jwt";

/// The audience every delivery proof names.
pub const AUDIENCE_DELIVERY: &str = "mcpg-gateway-delivery";

/// gRPC metadata a gateway sends when it opens the Channel: a fresh nonce
/// ([`new_nonce`]) for each Channel, which every delivery proof on that
/// Channel must carry.
pub const DELIVERY_NONCE_HEADER: &str = "mcpg-delivery-nonce";

/// gRPC metadata a gateway sends when it opens the Channel: the build version
/// of the running binary, which can differ from the version it registered
/// with once the binary is upgraded.
pub const AGENT_VERSION_HEADER: &str = "mcpg-agent-version";

/// gRPC metadata a gateway sends when it opens the Channel: an id the process
/// draws once at start and sends on every Channel it opens. The pods of a
/// managed instance share its uid, and this tells their Channels apart.
pub const AGENT_PROCESS_HEADER: &str = "mcpg-agent-process";

/// gRPC metadata a gateway sends when it opens the Channel: its heartbeat
/// interval in milliseconds. The control plane closes a Channel that misses
/// two heartbeats.
pub const AGENT_HEARTBEAT_HEADER: &str = "mcpg-agent-heartbeat-ms";

/// gRPC metadata on the `already_exists` answer to a Channel its instance's
/// live Channel holds the slot of: how many milliseconds until the slot frees
/// unless that Channel speaks again.
pub const CHANNEL_RETRY_AFTER_HEADER: &str = "mcpg-channel-retry-after-ms";

/// How long (`exp - iat`) a control plane signs a proof for. A live proof is
/// checked once, when its delivery arrives.
pub const DELIVERY_PROOF_LIFETIME_SECS: i64 = 5 * 60;

/// The longest lifetime (`exp - iat`) a gateway accepts on a proof, so a
/// misissued long-lived one is refused rather than accepted on its Channel
/// long after it was signed. A cached proof counts for
/// [`LAST_KNOWN_GOOD_SECS`] after its `iat`, whatever its `exp`.
pub const MAX_DELIVERY_PROOF_LIFETIME_SECS: i64 = 60 * 60;

/// How long after a proof's `iat` a restarted gateway counts the cached
/// licence that proof vouched for, while no control plane has answered it.
/// The licence's own expiry and grace still apply within it.
pub const LAST_KNOWN_GOOD_SECS: i64 = 24 * 60 * 60;

/// Clock skew allowed on `iat` and `exp`.
const LEEWAY_SECS: i64 = 60;

/// Random bytes in a nonce.
const NONCE_BYTES: usize = 32;

/// What a delivery proof says.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliveryProofClaims {
    pub iss: String,
    /// [`AUDIENCE_DELIVERY`].
    pub aud: String,
    /// The slug of the org the control plane enrolled the gateway into.
    pub org: String,
    /// [`license_digest`] of the licence delivered with the proof; the digest
    /// of the empty string when the org holds none.
    pub lic: String,
    /// The nonce the gateway sent when it opened the Channel.
    pub nonce: String,
    /// The instance uid the Channel is authenticated as.
    pub uid: String,
    pub iat: i64,
    pub exp: i64,
}

impl DeliveryProofClaims {
    /// Claims vouching that `license_jwt` (empty: no licence) goes to
    /// `org_slug` on the Channel instance `instance_uid` opened with `nonce`,
    /// valid for [`DELIVERY_PROOF_LIFETIME_SECS`] from `now`.
    pub fn new(
        issuer: &str,
        org_slug: &str,
        license_jwt: &str,
        nonce: &str,
        instance_uid: &str,
        now: i64,
    ) -> Self {
        DeliveryProofClaims {
            iss: issuer.to_owned(),
            aud: AUDIENCE_DELIVERY.to_owned(),
            org: org_slug.to_owned(),
            lic: license_digest(license_jwt),
            nonce: nonce.to_owned(),
            uid: instance_uid.to_owned(),
            iat: now,
            exp: now + DELIVERY_PROOF_LIFETIME_SECS,
        }
    }
}

/// The digest a proof names a licence by: SHA-256 of the token with
/// surrounding whitespace trimmed, base64url without padding.
pub fn license_digest(license_jwt: &str) -> String {
    b64url_encode(&Sha256::digest(license_jwt.trim().as_bytes()))
}

/// A fresh Channel nonce: 32 random bytes, base64url without padding.
pub fn new_nonce() -> String {
    use rand::Rng;
    let mut bytes = [0u8; NONCE_BYTES];
    rand::rng().fill_bytes(&mut bytes);
    b64url_encode(&bytes)
}

/// The JOSE header of a proof signed by the key with thumbprint `kid`.
pub fn delivery_proof_header(kid: &str) -> Header {
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(kid.to_owned());
    header.typ = Some(DELIVERY_PROOF_TYP.to_owned());
    header
}

/// Sign `claims` as a delivery proof with `key`, the `platform` issuer key
/// whose thumbprint is `kid`.
pub fn encode_delivery_proof(
    claims: &DeliveryProofClaims,
    key: &EncodingKey,
    kid: &str,
) -> Result<String, LicenseError> {
    jsonwebtoken::encode(&delivery_proof_header(kid), claims, key)
        .map_err(|e| LicenseError::DeliveryProof(format!("cannot sign: {e}")))
}

/// The delivery a gateway checks a proof against: what arrived, the nonce it
/// sent on the Channel it arrived on, and the instance uid that Channel is
/// authenticated as.
#[derive(Clone, Copy, Debug)]
pub struct ExpectedDelivery<'a> {
    pub nonce: &'a str,
    pub instance_uid: &'a str,
    pub org_slug: &'a str,
    pub license_jwt: &'a str,
    /// Whether the delivered licence marks non-production use. A staging
    /// key's proof vouches only for such a licence, or for none, so a leaked
    /// staging key cannot pass off a copied production licence.
    pub license_non_production: bool,
}

/// Verify `proof` for a delivery that just arrived on a Channel, at `now`
/// (unix seconds).
///
/// Checks: `alg` EdDSA and `typ` [`DELIVERY_PROOF_TYP`]; a `kid` naming a
/// trusted, unrevoked `platform` key; the signature and the audience; `iat`
/// and `exp` with 60 seconds of leeway and a lifetime of at most
/// [`MAX_DELIVERY_PROOF_LIFETIME_SECS`]; and that the nonce, the instance uid,
/// the org and the licence digest are the expected ones.
pub fn verify_delivery_proof(
    proof: &str,
    expected: &ExpectedDelivery<'_>,
    now: i64,
) -> Result<DeliveryProofClaims, LicenseError> {
    let claims = verify_bound(proof, expected, now)?;
    if claims.exp <= now - LEEWAY_SECS {
        return Err(LicenseError::DeliveryProof(format!(
            "it expired at {}",
            claims.exp
        )));
    }
    Ok(claims)
}

/// Verify a proof a gateway kept with the delivery it cached, on a restart at
/// `now`: every check of [`verify_delivery_proof`] against the nonce and the
/// instance uid it was kept with, except that the proof's own `exp` has
/// passed. It holds until [`LAST_KNOWN_GOOD_SECS`] after its `iat`; the
/// answer is that time.
pub fn verify_cached_delivery_proof(
    proof: &str,
    expected: &ExpectedDelivery<'_>,
    now: i64,
) -> Result<i64, LicenseError> {
    let claims = verify_bound(proof, expected, now)?;
    let until = claims.iat.saturating_add(LAST_KNOWN_GOOD_SECS);
    if until <= now {
        return Err(LicenseError::DeliveryProof(format!(
            "it was signed at {}, more than {LAST_KNOWN_GOOD_SECS} s ago",
            claims.iat
        )));
    }
    Ok(until)
}

/// The longest `kid` [`delivery_proof_kid`] hands back.
const MAX_REPORTED_KID_LEN: usize = 128;

/// The `kid` a proof's header names, read without verifying anything: what a
/// gateway reports about a proof it refused, so an operator can tell which
/// key it claims. Never a reason to trust the proof. `None` for a malformed
/// header, one with no `kid`, or a `kid` longer than any thumbprint.
pub fn delivery_proof_kid(proof: &str) -> Option<String> {
    jsonwebtoken::decode_header(proof.trim())
        .ok()?
        .kid
        .filter(|kid| kid.len() <= MAX_REPORTED_KID_LEN)
}

/// The checks both kinds of verification share: everything but `exp`.
fn verify_bound(
    proof: &str,
    expected: &ExpectedDelivery<'_>,
    now: i64,
) -> Result<DeliveryProofClaims, LicenseError> {
    let refuse = |why: String| LicenseError::DeliveryProof(why);
    if expected.nonce.is_empty() {
        return Err(refuse("the Channel carried no nonce to bind it to".into()));
    }
    if expected.instance_uid.is_empty() {
        return Err(refuse(
            "the Channel's instance uid is unknown, so nothing binds it".into(),
        ));
    }
    let proof = proof.trim();
    if proof.is_empty() {
        return Err(refuse("the delivery carries none".into()));
    }
    let header =
        jsonwebtoken::decode_header(proof).map_err(|e| refuse(format!("malformed header: {e}")))?;
    if header.alg != Algorithm::EdDSA {
        return Err(refuse(format!("algorithm {:?} is not EdDSA", header.alg)));
    }
    if header.typ.as_deref() != Some(DELIVERY_PROOF_TYP) {
        return Err(refuse(format!(
            "header typ is {:?}, not `{DELIVERY_PROOF_TYP}`",
            header.typ.as_deref().unwrap_or("")
        )));
    }
    let kid = header
        .kid
        .ok_or_else(|| LicenseError::UntrustedIssuerKey("(no kid)".to_owned()))?;
    let issuer = trusted_issuer_key(&kid)?;
    if issuer.role != IssuerRole::Platform {
        return Err(LicenseError::IssuerRoleNotAccepted {
            kid,
            role: issuer.role.as_str(),
        });
    }

    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_audience(&[AUDIENCE_DELIVERY]);
    validation.set_required_spec_claims(&["exp", "aud"]);
    // Judged by the callers against `now`, so the caller's clock decides.
    validation.validate_exp = false;
    validation.validate_nbf = false;
    let key = DecodingKey::from_ed_der(issuer.key.to_bytes().as_ref());
    let claims = jsonwebtoken::decode::<DeliveryProofClaims>(proof, &key, &validation)
        .map_err(|e| refuse(e.to_string()))?
        .claims;

    if claims.iat > now + LEEWAY_SECS {
        return Err(refuse(format!(
            "it is issued in the future ({})",
            claims.iat
        )));
    }
    if claims.exp - claims.iat > MAX_DELIVERY_PROOF_LIFETIME_SECS {
        return Err(refuse(format!(
            "it is valid for {} s, longer than {MAX_DELIVERY_PROOF_LIFETIME_SECS} s",
            claims.exp - claims.iat
        )));
    }
    if claims.nonce != expected.nonce {
        return Err(refuse(
            "it names another Channel's nonce than the one this gateway sent".into(),
        ));
    }
    if claims.uid != expected.instance_uid {
        return Err(refuse(format!(
            "it is for instance `{}`, not `{}`",
            claims.uid, expected.instance_uid
        )));
    }
    if claims.org != expected.org_slug {
        return Err(refuse(format!(
            "it is for org `{}`, not `{}`",
            claims.org, expected.org_slug
        )));
    }
    if claims.lic != license_digest(expected.license_jwt) {
        return Err(refuse("it vouches for another licence".into()));
    }
    if issuer.environment == KeyEnvironment::Staging
        && !expected.license_jwt.trim().is_empty()
        && !expected.license_non_production
    {
        return Err(LicenseError::StagingKeyProductionLicense(kid));
    }
    Ok(claims)
}

/// Sign proofs in tests with keys the test trusts. Compiled only with debug
/// assertions, like the trust override it builds on.
#[cfg(debug_assertions)]
pub mod test_proof {
    use ed25519_dalek::SigningKey;
    use ed25519_dalek::pkcs8::EncodePrivateKey;

    use super::*;
    use crate::trust::thumbprint_kid;

    /// Claims vouching for `license_jwt` delivered to `org_slug` on the
    /// Channel instance `uid` opened with `nonce`, valid for five minutes from
    /// `now`.
    pub fn claims(
        nonce: &str,
        uid: &str,
        org_slug: &str,
        license_jwt: &str,
        now: i64,
    ) -> DeliveryProofClaims {
        DeliveryProofClaims::new("https://cp.test", org_slug, license_jwt, nonce, uid, now)
    }

    /// `claims` signed by `key`.
    pub fn sign(claims: &DeliveryProofClaims, key: &SigningKey) -> String {
        let der = key.to_pkcs8_der().expect("encode an Ed25519 key as PKCS#8");
        encode_delivery_proof(
            claims,
            &EncodingKey::from_ed_der(der.as_bytes()),
            &thumbprint_kid(&key.verifying_key()),
        )
        .expect("sign a delivery proof")
    }
}

#[cfg(all(test, debug_assertions))]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::test_proof::{claims, sign};
    use super::*;
    use crate::trust::test_override::trusted_signing_key;

    const NOW: i64 = 1_900_000_000;
    const UID: &str = "gw-1";

    fn expected<'a>(nonce: &'a str, lic: &'a str) -> ExpectedDelivery<'a> {
        ExpectedDelivery {
            nonce,
            instance_uid: UID,
            org_slug: "acme",
            license_jwt: lic,
            license_non_production: false,
        }
    }

    fn platform_key() -> SigningKey {
        trusted_signing_key(IssuerRole::Platform, KeyEnvironment::Production)
    }

    #[test]
    fn a_proof_for_this_channel_and_licence_verifies() {
        let key = platform_key();
        let nonce = new_nonce();
        let proof = sign(&claims(&nonce, UID, "acme", "h.p.s", NOW), &key);
        let verified = verify_delivery_proof(&proof, &expected(&nonce, "h.p.s"), NOW).unwrap();
        assert_eq!(
            (verified.org.as_str(), verified.uid.as_str()),
            ("acme", UID)
        );
        assert_eq!(verified.exp - verified.iat, DELIVERY_PROOF_LIFETIME_SECS);
        // An empty delivery (the org holds no licence) is vouched for too.
        let none = sign(&claims(&nonce, UID, "acme", "", NOW), &key);
        verify_delivery_proof(&none, &expected(&nonce, ""), NOW).unwrap();
    }

    #[test]
    fn a_proof_proves_only_its_own_channel_instance_org_and_licence() {
        let key = platform_key();
        let nonce = new_nonce();
        let proof = sign(&claims(&nonce, UID, "acme", "h.p.s", NOW), &key);
        let other_channel = new_nonce();
        for (nonce, uid, org, lic) in [
            (other_channel.as_str(), UID, "acme", "h.p.s"),
            (nonce.as_str(), "gw-2", "acme", "h.p.s"),
            (nonce.as_str(), UID, "globex", "h.p.s"),
            (nonce.as_str(), UID, "acme", "other.licence.jwt"),
            ("", UID, "acme", "h.p.s"),
            (nonce.as_str(), "", "acme", "h.p.s"),
        ] {
            let expect = ExpectedDelivery {
                nonce,
                instance_uid: uid,
                org_slug: org,
                license_jwt: lic,
                license_non_production: false,
            };
            assert!(
                verify_delivery_proof(&proof, &expect, NOW).is_err(),
                "{nonce} {uid} {org} {lic}"
            );
            assert!(
                verify_cached_delivery_proof(&proof, &expect, NOW).is_err(),
                "cached: {nonce} {uid} {org} {lic}"
            );
        }
    }

    /// The licence keys sign no proof: a proof is a platform key's alone.
    #[test]
    fn only_a_trusted_platform_key_signs_a_proof() {
        let nonce = new_nonce();
        let c = claims(&nonce, UID, "acme", "h.p.s", NOW);
        for role in [IssuerRole::Cloud, IssuerRole::SelfHost] {
            let licence_key = trusted_signing_key(role, KeyEnvironment::Production);
            assert!(matches!(
                verify_delivery_proof(&sign(&c, &licence_key), &expected(&nonce, "h.p.s"), NOW),
                Err(LicenseError::IssuerRoleNotAccepted { .. })
            ));
        }
        let untrusted = SigningKey::generate(&mut rand::rng());
        assert!(matches!(
            verify_delivery_proof(&sign(&c, &untrusted), &expected(&nonce, "h.p.s"), NOW),
            Err(LicenseError::UntrustedIssuerKey(_))
        ));
    }

    #[test]
    fn a_licence_is_not_a_proof() {
        let key = platform_key();
        let nonce = new_nonce();
        let c = claims(&nonce, UID, "acme", "h.p.s", NOW);
        let der = ed25519_dalek::pkcs8::EncodePrivateKey::to_pkcs8_der(&key).unwrap();
        let mut header = delivery_proof_header(&crate::trust::thumbprint_kid(&key.verifying_key()));
        header.typ = Some(crate::trust::LICENSE_JWT_TYP.to_owned());
        let as_licence =
            jsonwebtoken::encode(&header, &c, &EncodingKey::from_ed_der(der.as_bytes())).unwrap();
        assert!(verify_delivery_proof(&as_licence, &expected(&nonce, "h.p.s"), NOW).is_err());
        let mut wrong_aud = c.clone();
        wrong_aud.aud = crate::license::AUDIENCE_GATEWAY_MANAGED.into();
        assert!(
            verify_delivery_proof(&sign(&wrong_aud, &key), &expected(&nonce, "h.p.s"), NOW)
                .is_err()
        );
    }

    #[test]
    fn a_stale_future_or_long_lived_proof_is_refused() {
        let key = platform_key();
        let nonce = new_nonce();
        let at = |iat: i64, exp: i64| {
            let mut c = claims(&nonce, UID, "acme", "h.p.s", NOW);
            c.iat = iat;
            c.exp = exp;
            sign(&c, &key)
        };
        let e = expected(&nonce, "h.p.s");
        assert!(verify_delivery_proof(&at(NOW - 600, NOW - 120), &e, NOW).is_err());
        assert!(verify_delivery_proof(&at(NOW + 600, NOW + 900), &e, NOW).is_err());
        assert!(
            verify_delivery_proof(
                &at(NOW, NOW + MAX_DELIVERY_PROOF_LIFETIME_SECS + 1),
                &e,
                NOW
            )
            .is_err()
        );
        verify_delivery_proof(&at(NOW - 30, NOW + 30), &e, NOW).unwrap();
    }

    /// A kept proof vouches for its cached delivery for a day after it was
    /// signed, its own expiry long past, and not a second longer.
    #[test]
    fn a_kept_proof_holds_for_a_day_after_it_was_signed() {
        let key = platform_key();
        let nonce = new_nonce();
        let proof = sign(&claims(&nonce, UID, "acme", "h.p.s", NOW), &key);
        let e = expected(&nonce, "h.p.s");
        let later = NOW + LAST_KNOWN_GOOD_SECS - 1;
        assert!(verify_delivery_proof(&proof, &e, later).is_err(), "expired");
        assert_eq!(
            verify_cached_delivery_proof(&proof, &e, later).unwrap(),
            NOW + LAST_KNOWN_GOOD_SECS
        );
        assert!(verify_cached_delivery_proof(&proof, &e, NOW + LAST_KNOWN_GOOD_SECS).is_err());
        let future = sign(&claims(&nonce, UID, "acme", "h.p.s", NOW + 600), &key);
        assert!(verify_cached_delivery_proof(&future, &e, NOW).is_err());
    }

    #[test]
    fn a_staging_proof_vouches_only_for_a_non_production_licence() {
        let staging = trusted_signing_key(IssuerRole::Platform, KeyEnvironment::Staging);
        let nonce = new_nonce();
        let proof = sign(&claims(&nonce, UID, "acme", "h.p.s", NOW), &staging);
        assert!(matches!(
            verify_delivery_proof(&proof, &expected(&nonce, "h.p.s"), NOW),
            Err(LicenseError::StagingKeyProductionLicense(_))
        ));
        assert!(matches!(
            verify_cached_delivery_proof(&proof, &expected(&nonce, "h.p.s"), NOW),
            Err(LicenseError::StagingKeyProductionLicense(_))
        ));
        let marked = ExpectedDelivery {
            license_non_production: true,
            ..expected(&nonce, "h.p.s")
        };
        verify_delivery_proof(&proof, &marked, NOW).unwrap();
        let none = sign(&claims(&nonce, UID, "acme", "", NOW), &staging);
        verify_delivery_proof(&none, &expected(&nonce, ""), NOW).unwrap();
    }

    /// The `kid` of a proof reads back whether or not the proof verifies,
    /// and only from a well-formed header.
    #[test]
    fn a_proofs_kid_reads_back_unverified() {
        let nonce = new_nonce();
        let untrusted = SigningKey::generate(&mut rand::rng());
        let proof = sign(&claims(&nonce, UID, "acme", "h.p.s", NOW), &untrusted);
        assert_eq!(
            delivery_proof_kid(&format!(" {proof}\n")),
            Some(crate::trust::thumbprint_kid(&untrusted.verifying_key()))
        );
        assert_eq!(delivery_proof_kid(""), None);
        assert_eq!(delivery_proof_kid("not.a.jwt"), None);
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("k".repeat(MAX_REPORTED_KID_LEN + 1));
        let long = jsonwebtoken::encode(
            &header,
            &claims(&nonce, UID, "acme", "h.p.s", NOW),
            &EncodingKey::from_secret(b"s"),
        )
        .unwrap();
        assert_eq!(
            delivery_proof_kid(&long),
            None,
            "longer than any thumbprint"
        );
    }

    #[test]
    fn nonces_are_fresh_and_the_digest_ignores_surrounding_whitespace() {
        assert_ne!(new_nonce(), new_nonce());
        assert_eq!(new_nonce().len(), 43);
        assert_eq!(license_digest(" a.b.c\n"), license_digest("a.b.c"));
        assert_ne!(license_digest("a.b.c"), license_digest(""));
    }
}
