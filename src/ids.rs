//! Strongly-typed ids used across the CP.
//!
//! Each id wraps a `Uuid` (or `String` for human-readable
//! slugs). Newtypes prevent the "I passed an OrgId where a
//! WorkspaceId was expected" class of bug.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

macro_rules! id_newtype {
    ($name:ident, $inner:ty, $kind:literal) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub $inner);

        impl $name {
            pub fn new() -> Self {
                Self(Uuid::now_v7())
            }
            pub fn into_inner(self) -> $inner {
                self.0
            }
            pub fn as_uuid(&self) -> &$inner {
                &self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl FromStr for $name {
            type Err = uuid::Error;
            fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
                Ok(Self(Uuid::parse_str(s)?))
            }
        }

        impl From<$inner> for $name {
            fn from(v: $inner) -> Self {
                Self(v)
            }
        }
    };
}

id_newtype!(OrgId, Uuid, "org");
id_newtype!(WorkspaceId, Uuid, "workspace");
id_newtype!(EnvironmentId, Uuid, "environment");
id_newtype!(InstanceId, Uuid, "instance");
id_newtype!(UserId, Uuid, "user");
id_newtype!(ServiceTokenId, Uuid, "svctoken");

impl InstanceId {
    /// Parse a wire `instance_uid` string into a typed id. A cloud-minted uid is
    /// the canonical [`InstanceId`] (a UUIDv7) rendered as a string; this is the
    /// enrollment-adoption path's parser.
    pub fn from_uid_str(s: &str) -> Result<Self, uuid::Error> {
        s.parse()
    }
}

/// True when `s` is a *canonical* instance uid — a UUID, as minted by the
/// control plane when it pre-creates an instance row. Self-host gateways present
/// free-form uids (e.g. `host-ab12cd`), which are not canonical and are never
/// adopted into a pre-created row; only canonical uids bind to a bootstrap token.
pub fn is_canonical_instance_uid(s: &str) -> bool {
    Uuid::parse_str(s).is_ok()
}

/// 256-bit opaque session identifier (not a UUID; cryptographic).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionId(pub Vec<u8>);

impl SessionId {
    pub fn new() -> Self {
        let mut bytes = vec![0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut bytes);
        Self(bytes)
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

/// Human-readable Org slug — stable, URL-safe.
/// Pattern: `[a-z0-9-]{2,40}`. Used in subdomains
/// (`acme.mcpg.cloud`) and audit logs.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OrgSlug(String);

impl OrgSlug {
    /// Construct a validated slug; returns `Err` if the slug
    /// doesn't match the pattern.
    pub fn parse(s: impl Into<String>) -> std::result::Result<Self, SlugError> {
        let s = s.into();
        validate_slug(&s, 2, 40, true)?;
        Ok(Self(s))
    }
    /// The platform's bootstrap singleton org slug (`default`). It is
    /// RESERVED (see [`RESERVED_SLUGS`]) precisely so no tenant signal —
    /// a federation license `tenant_slug` or a generic id_token claim —
    /// can ever resolve to the shared bootstrap org and merge tenants.
    /// The only legitimate holder is the Tier-0 / shared org created by
    /// `OrgsRepo::ensure_default`, which constructs it here, bypassing
    /// the reserved check.
    pub fn bootstrap_default() -> Self {
        Self(DEFAULT_ORG_SLUG.to_string())
    }
    /// Reconstruct a slug from an ALREADY-PERSISTED value (a DB row),
    /// bypassing validation. The value was validated by `parse` when it
    /// was created, so we trust it on read-back. This must NOT be used
    /// for caller/operator input — only for rehydrating stored rows —
    /// because it preserves the value verbatim (so a corrupt/legacy
    /// slug stays unique to its row rather than silently aliasing onto
    /// the reserved `default` slug, which doubles as a tenant-isolation
    /// key for crypto AAD and namespaces).
    pub fn from_stored(s: impl Into<String>) -> Self {
        Self(s.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub fn into_inner(self) -> String {
        self.0
    }
}

/// Slug of the bootstrap / Tier-0 shared org. Reserved — never
/// assignable to a tenant. See [`OrgSlug::bootstrap_default`].
pub const DEFAULT_ORG_SLUG: &str = "default";

impl fmt::Display for OrgSlug {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WorkspaceSlug(String);

impl WorkspaceSlug {
    pub fn parse(s: impl Into<String>) -> std::result::Result<Self, SlugError> {
        let s = s.into();
        validate_slug(&s, 2, 40, false)?;
        Ok(Self(s))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Display for WorkspaceSlug {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Human-readable instance slug — the globally-unique DNS label that addresses
/// a deployed gateway at `{slug}.mcpg.cloud/mcp`. Reserved-checked (it becomes
/// a public subdomain) and unique across the whole fleet, not per-tenant.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct InstanceSlug(String);

impl InstanceSlug {
    pub fn parse(s: impl Into<String>) -> std::result::Result<Self, SlugError> {
        let s = s.into();
        validate_slug(&s, 2, 40, true)?;
        Ok(Self(s))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Display for InstanceSlug {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A customer-supplied custom domain (FQDN) for a published gateway —
/// e.g. `mcp.example.com`. Normalised on parse: lowercased, trailing root
/// dot stripped. RFC 1123 host shape: 2+ labels, each 1–63 chars of
/// `[a-z0-9-]` without boundary hyphens, ≤253 chars total. The last label
/// must not be all-numeric (rejects IPv4 literals); `:` is rejected
/// outright (no ports / IPv6). Deliberately NOT reserved-checked per label
/// — it's an external name; what it must never be is a name under the
/// platform's own suffix, which the caller checks against its configured
/// `tenant_subdomain_suffix` (the platform wildcard) since this crate
/// doesn't know the deployment's base domain.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CustomHostname(String);

impl CustomHostname {
    pub fn parse(s: impl Into<String>) -> std::result::Result<Self, HostnameError> {
        let raw: String = s.into();
        let h = raw.trim().trim_end_matches('.').to_ascii_lowercase();
        if h.is_empty() {
            return Err(HostnameError::Empty);
        }
        if h.len() > 253 {
            return Err(HostnameError::TooLong(h));
        }
        if h.contains(':') {
            return Err(HostnameError::InvalidChars(h));
        }
        let labels: Vec<&str> = h.split('.').collect();
        if labels.len() < 2 {
            return Err(HostnameError::NotFullyQualified(h));
        }
        for label in &labels {
            if label.is_empty() || label.len() > 63 {
                return Err(HostnameError::BadLabel(h.clone()));
            }
            if label.starts_with('-') || label.ends_with('-') {
                return Err(HostnameError::BadLabel(h.clone()));
            }
            if !label
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            {
                return Err(HostnameError::InvalidChars(h.clone()));
            }
        }
        // An all-numeric final label means an IP literal (1.2.3.4), not a name.
        if labels
            .last()
            .is_some_and(|l| l.chars().all(|c| c.is_ascii_digit()))
        {
            return Err(HostnameError::IpLiteral(h));
        }
        Ok(Self(h))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Display for CustomHostname {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum HostnameError {
    #[error("hostname is empty")]
    Empty,
    #[error("hostname `{0}` is too long (maximum 253 chars)")]
    TooLong(String),
    #[error(
        "hostname `{0}` must be a fully-qualified domain (at least two labels, e.g. mcp.example.com)"
    )]
    NotFullyQualified(String),
    #[error(
        "hostname `{0}` has an invalid label (each label is 1-63 chars, no leading/trailing hyphen)"
    )]
    BadLabel(String),
    #[error("hostname `{0}` contains invalid characters (only [a-z0-9-] and dots allowed)")]
    InvalidChars(String),
    #[error("`{0}` is an IP literal, not a domain name")]
    IpLiteral(String),
}

#[derive(Debug, thiserror::Error)]
pub enum SlugError {
    #[error("slug `{0}` is too short (minimum {1} chars)")]
    TooShort(String, usize),
    #[error("slug `{0}` is too long (maximum {1} chars)")]
    TooLong(String, usize),
    #[error("slug `{0}` contains invalid characters (only [a-z0-9-] allowed)")]
    InvalidChars(String),
    #[error("slug `{0}` cannot start or end with `-`")]
    BoundaryHyphen(String),
    #[error("slug `{0}` is reserved by the platform")]
    Reserved(String),
}

/// Slugs the platform reserves for its own hostnames / path segments on
/// `{orgslug}.mcpg.cloud` and `{instanceid}.mcpg.cloud`. Never assignable as an
/// org or instance slug. Superset of the host-classifier's old private list.
pub const RESERVED_SLUGS: &[&str] = &[
    "cp",
    "app",
    "api",
    "auth",
    "www",
    "admin",
    "portal",
    "dashboard",
    "docs",
    "status",
    "cdn",
    "static",
    "assets",
    "mcp",
    // The hosted inspector's own hostname; a tenant claiming it would
    // serve its own page at the URL operators are told to trust.
    "inspector",
    "healthz",
    "readyz",
    "metrics",
    "v1",
    "_internal",
    "well-known",
    "login",
    "logout",
    "callback",
    "enroll",
    // The shared bootstrap org's slug — reserved so no tenant signal can
    // resolve into it (a cross-tenant merge). See `OrgSlug::bootstrap_default`.
    DEFAULT_ORG_SLUG,
];

/// True when `s` is platform-reserved and must not be an org/instance slug.
pub fn is_reserved(s: &str) -> bool {
    RESERVED_SLUGS.contains(&s)
}

fn validate_slug(
    s: &str,
    min: usize,
    max: usize,
    reserved: bool,
) -> std::result::Result<(), SlugError> {
    if s.len() < min {
        return Err(SlugError::TooShort(s.to_owned(), min));
    }
    if s.len() > max {
        return Err(SlugError::TooLong(s.to_owned(), max));
    }
    if s.starts_with('-') || s.ends_with('-') {
        return Err(SlugError::BoundaryHyphen(s.to_owned()));
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(SlugError::InvalidChars(s.to_owned()));
    }
    if reserved && is_reserved(s) {
        return Err(SlugError::Reserved(s.to_owned()));
    }
    Ok(())
}

/// Readable, lossy slug fragment from a raw claim value: lowercase,
/// every run of non-`[a-z0-9]` collapsed to a single `-`, no boundary
/// hyphens. May be empty if `raw` has no alphanumerics. This alone is
/// MANY-TO-ONE (`Acme Inc` and `acme.inc` both → `acme-inc`), so it is
/// only ever a *prefix* — `tenant_claim_slug` appends a hash to keep
/// the org mapping injective.
fn slug_prefix(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut prev_dash = false;
    for ch in raw.chars() {
        let c = ch.to_ascii_lowercase();
        if c.is_ascii_alphanumeric() {
            out.push(c);
            prev_dash = false;
        } else if !out.is_empty() && !prev_dash {
            out.push('-');
            prev_dash = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    out
}

/// Derive an INJECTIVE org slug from a generic-IdP tenant claim value.
///
/// A plain slugification is many-to-one, so two distinct enterprises
/// behind one IdP whose claim values collapse to the same slug
/// (`Acme Inc` vs `acme.inc`, or anything sharing a 40-char prefix)
/// would be MERGED into one org — the inverse of the leak this feature
/// prevents. To stop that we append a short deterministic hash of the
/// case-normalised claim value, so distinct values get distinct slugs
/// while the same value (modulo case / surrounding whitespace) always
/// maps to the same org. The readable prefix is retained for operator
/// legibility. Returns `None` for a blank value (caller fails closed).
///
/// SINGLE SOURCE OF TRUTH: the CP's login tenant-resolution AND the
/// operator tooling (`mcpg admin org create --tenant-claim`) both
/// derive through this fn, so a tenant seeded from a claim value always
/// matches the org that claim resolves to at login.
pub fn tenant_claim_slug(raw: &str) -> Option<String> {
    use sha2::Digest as _;
    let norm = raw.trim();
    if norm.is_empty() {
        return None;
    }
    // 12 hex chars = 48 bits of disambiguator over the case-folded
    // value. Case-folding means `Acme`/`acme`/`ACME` share an org
    // (claim-case drift is the same tenant); genuinely different values
    // do not.
    let mut h = sha2::Sha256::new();
    h.update(norm.to_lowercase().as_bytes());
    let digest = h.finalize();
    let hash: String = digest.iter().take(6).map(|b| format!("{b:02x}")).collect();

    // Keep the readable prefix within the 40-char ceiling, leaving room
    // for `-<hash>`.
    let budget = 40 - 1 - hash.len();
    let prefix: String = slug_prefix(norm).chars().take(budget).collect();
    let prefix = prefix.trim_matches('-');
    let candidate = if prefix.is_empty() {
        hash
    } else {
        format!("{prefix}-{hash}")
    };
    // Defer the canonical rules (length, charset, reserved) to the
    // validator so this stays in lock-step with it.
    OrgSlug::parse(candidate).ok().map(|slug| slug.into_inner())
}

#[cfg(test)]
mod tests {

    #[test]
    fn slug_prefix_normalises_case_spaces_and_punctuation() {
        assert_eq!(slug_prefix("Acme Inc"), "acme-inc");
        assert_eq!(slug_prefix("acme.com"), "acme-com");
        assert_eq!(slug_prefix("  Trim  Me  "), "trim-me");
        // Runs of separators collapse to a single hyphen; boundaries trimmed.
        assert_eq!(slug_prefix("a__b///c"), "a-b-c");
        assert_eq!(slug_prefix("---"), "");
        assert_eq!(slug_prefix(""), "");
    }

    #[test]
    fn tenant_claim_slug_round_trips_for_operator_tooling() {
        // The CLI (`--tenant-claim`) and the CP login path both derive
        // through this single fn — same value, same slug, always.
        let s = tenant_claim_slug("acme.com").expect("valid");
        assert!(s.starts_with("acme-com-"));
        assert_eq!(s, tenant_claim_slug("ACME.COM").unwrap(), "case-folded");
        assert!(tenant_claim_slug("   ").is_none(), "blank rejected");
    }
    use super::*;

    #[test]
    fn slug_accepts_valid() {
        assert!(OrgSlug::parse("acme").is_ok());
        assert!(OrgSlug::parse("acme-corp").is_ok());
        assert!(OrgSlug::parse("a1-b2-c3").is_ok());
    }

    #[test]
    fn slug_rejects_invalid() {
        assert!(OrgSlug::parse("a").is_err()); // too short
        assert!(OrgSlug::parse("Acme").is_err()); // uppercase
        assert!(OrgSlug::parse("acme!").is_err()); // bad char
        assert!(OrgSlug::parse("-acme").is_err()); // leading dash
        assert!(OrgSlug::parse("acme-").is_err()); // trailing dash
    }

    #[test]
    fn org_slug_rejects_every_reserved() {
        for r in RESERVED_SLUGS {
            // skip entries that fail charset first (e.g. `_internal`); the rest
            // must be rejected specifically as Reserved.
            if r.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
                && r.len() >= 2
            {
                assert!(
                    matches!(OrgSlug::parse(*r), Err(SlugError::Reserved(_))),
                    "expected {r} reserved"
                );
            }
        }
        assert!(OrgSlug::parse("acme").is_ok());
    }

    #[test]
    fn default_is_reserved_but_bootstrap_and_stored_bypass() {
        // A tenant signal can never `parse` its way to the shared org slug…
        assert!(matches!(
            OrgSlug::parse("default"),
            Err(SlugError::Reserved(_))
        ));
        // …but the bootstrap org and DB read-back construct it directly.
        assert_eq!(OrgSlug::bootstrap_default().as_str(), DEFAULT_ORG_SLUG);
        assert_eq!(OrgSlug::from_stored("default").as_str(), "default");
        // `from_stored` rehydrates ANY persisted value verbatim (so a
        // corrupt/legacy slug stays unique, not aliased onto `default`).
        assert_eq!(
            OrgSlug::from_stored("Legacy_Corrupt").as_str(),
            "Legacy_Corrupt"
        );
    }

    #[test]
    fn workspace_slug_is_not_reserved_checked() {
        // workspaces are not subdomains, so reserved words are allowed.
        assert!(WorkspaceSlug::parse("api").is_ok());
        assert!(WorkspaceSlug::parse("admin").is_ok());
    }

    #[test]
    fn instance_slug_rules() {
        assert!(InstanceSlug::parse("edge").is_ok());
        assert!(InstanceSlug::parse("edge-1").is_ok());
        assert!(matches!(
            InstanceSlug::parse("mcp"),
            Err(SlugError::Reserved(_))
        ));
        assert!(matches!(
            InstanceSlug::parse("api"),
            Err(SlugError::Reserved(_))
        ));
        assert!(InstanceSlug::parse("Edge").is_err()); // uppercase
        assert!(InstanceSlug::parse("-edge").is_err()); // leading dash
        assert!(InstanceSlug::parse("edge-").is_err()); // trailing dash
        assert!(InstanceSlug::parse("e").is_err()); // too short
    }

    #[test]
    fn ids_are_distinct_types() {
        // Compile-time check: passing OrgId where WorkspaceId is
        // expected won't compile. Just confirm constructors work.
        let _o = OrgId::new();
        let _w = WorkspaceId::new();
    }

    #[test]
    fn session_id_is_random() {
        let a = SessionId::new();
        let b = SessionId::new();
        assert_ne!(a, b);
        assert_eq!(a.as_bytes().len(), 32);
    }

    #[test]
    fn custom_hostname_parses_and_normalises() {
        let h = CustomHostname::parse(" MCP.Example.COM. ").unwrap();
        assert_eq!(
            h.as_str(),
            "mcp.example.com",
            "trimmed, lowercased, root dot stripped"
        );
        assert!(
            CustomHostname::parse("a.io").is_ok(),
            "minimal two-label name"
        );
        assert!(
            CustomHostname::parse("xn--bcher-kva.example").is_ok(),
            "punycode A-labels pass (IDNA conversion is the caller's concern)"
        );
    }

    #[test]
    fn custom_hostname_rejects_bad_shapes() {
        assert!(matches!(
            CustomHostname::parse(""),
            Err(HostnameError::Empty)
        ));
        assert!(matches!(
            CustomHostname::parse("localhost"),
            Err(HostnameError::NotFullyQualified(_))
        ));
        assert!(matches!(
            CustomHostname::parse("1.2.3.4"),
            Err(HostnameError::IpLiteral(_))
        ));
        assert!(matches!(
            CustomHostname::parse("mcp.example.com:8443"),
            Err(HostnameError::InvalidChars(_))
        ));
        assert!(matches!(
            CustomHostname::parse("bad_label.example.com"),
            Err(HostnameError::InvalidChars(_))
        ));
        assert!(matches!(
            CustomHostname::parse("-x.example.com"),
            Err(HostnameError::BadLabel(_))
        ));
        assert!(matches!(
            CustomHostname::parse("a..example.com"),
            Err(HostnameError::BadLabel(_))
        ));
        let long = format!("{}.example.com", "a".repeat(64));
        assert!(matches!(
            CustomHostname::parse(long),
            Err(HostnameError::BadLabel(_))
        ));
        let too_long = format!("{}.com", "a.".repeat(130));
        assert!(matches!(
            CustomHostname::parse(too_long),
            Err(HostnameError::TooLong(_))
        ));
    }
}
