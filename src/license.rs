//! License JWT — the cryptographic carrier of plan tier, plugin
//! entitlements, quotas, and feature flags.
//!
//! License tokens are Ed25519-signed JWTs verified offline by both
//! the CP and the gateway.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use globset::{Glob, GlobSetBuilder};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::ids::OrgId;

/// All claims carried by a license JWT.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LicenseClaims {
    /// `iss` — issuer URL. `"https://auth.mcpg.dev"` for
    /// federation-issued; `"cli:mcpg-license"` for offline.
    pub iss: String,
    /// `sub` — `"tenant:<uuid>"` identifying the owning Org.
    pub sub: String,
    /// `aud` — must include `"mcpg-cp"` and/or `"mcpg-gateway"`.
    pub aud: Vec<String>,
    /// `iat` / `exp` / `nbf` — standard JWT timing claims.
    pub iat: i64,
    pub exp: i64,
    pub nbf: i64,
    /// `jti` — unique token id; supports targeted revocation.
    pub jti: String,
    /// `lic_ver` — major schema version. CPs refuse unknown
    /// majors.
    pub lic_ver: u32,

    /// Tenant identifier (UUID). Mirrors the Org's `id`.
    pub tenant_id: OrgId,
    /// Tenant slug. Mirrors the Org's slug.
    pub tenant_slug: String,
    /// Plan tier — `community` | `pro` | `team` | `enterprise`.
    ///
    /// That list is the whole vocabulary; the federation's `PLANS` allowlist
    /// is its authority and `plan_envelope` gives each one its quotas. Any
    /// other value falls back to the community envelope, so an unrecognised
    /// plan is under-entitled rather than refused.
    pub plan: String,

    /// Glob patterns of plugin ids the tenant may install.
    /// Examples: `core.*`, `policy.cedar`, `*` (sovereign).
    pub plugin_entitlements: Vec<String>,

    /// Feature flags — gate platform-level features. Examples:
    /// `audit_ledger`, `sso`, `multi_workspace`.
    pub features: Vec<String>,

    /// Per-resource limits.
    pub quotas: Quotas,

    /// Optional metadata; not enforced.
    #[serde(default)]
    pub metadata: serde_json::Value,

    /// Subscription-lapse grace timing (when set by federation).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grace: Option<GraceWindow>,

    /// Compliance boundary this tenant's data and workloads are confined to
    /// (`eu`, `us`, `gov`). Empty means the platform's default domain.
    ///
    /// Not a preference. The control plane serving a tenant and the cells its
    /// gateways run on must both be in this domain, and a mismatch is refused
    /// rather than scored down.
    #[serde(default)]
    pub residency_domain: String,

    /// Glob patterns of regions this tenant may target when publishing.
    /// Empty means the platform default region only — region choice is priced
    /// infrastructure, so a plan that does not mention regions does not get to
    /// pick one.
    #[serde(default)]
    pub allowed_regions: Vec<String>,

    /// Marks a customer-sovereign install. Verification rules
    /// differ slightly here: no revocation-list fetch.
    #[serde(default)]
    pub sovereign: bool,
    /// Marks air-gapped operation. CP refuses to phone home for
    /// license refresh when set.
    #[serde(default)]
    pub airgap: bool,

    /// Support/SLA tier — one of [`SUPPORT_TIERS`] (`none` | `business` |
    /// `enterprise` | `mission_critical`). Orthogonal to `plan`: a self-host
    /// enterprise install may carry any support tier. The tier drives the
    /// support-channel feature flags ([`FEATURE_SUPPORT_LTS`] /
    /// [`FEATURE_SUPPORT_FIPS`] / [`FEATURE_SUPPORT_CVE_RESPONSE`]) and is
    /// surfaced by the CP admin and `mcpg-license verify`. Defaults to `none`,
    /// so tokens minted before this field existed deserialize unchanged.
    #[serde(default = "default_support_tier")]
    pub support_tier: String,

    /// Commercial shape of the license — one of [`LICENSE_CLASSES`]
    /// (`subscription` | `capacity` | `site`). Reporting only: the enforceable
    /// caps live in [`Quotas`] (a `capacity` / `site` license carries the
    /// instance and tool-call ceilings its contract sets, or `0` for
    /// unlimited). Defaults to `subscription`.
    #[serde(default = "default_license_class")]
    pub license_class: String,

    /// The federation user this licence was minted for, when it was minted
    /// through an interactive login. `None` for a licence issued by slug over
    /// the broker, which has no user, and for every token minted before this
    /// field existed.
    ///
    /// A licence names a tenant but otherwise proves nothing about who is
    /// presenting it, which is why a caller-supplied one may not join an org
    /// that already has members. This claim is what makes the legitimate case
    /// distinguishable: it is inside the signed payload, so the federation —
    /// and only the federation — can attest that this licence was issued to
    /// this subject. A control plane can then let that subject join, while
    /// still refusing an unrelated presenter.
    #[serde(default)]
    pub issued_to: Option<String>,
}

/// Support tier assigned when a token omits `support_tier`.
pub const SUPPORT_TIER_NONE: &str = "none";
/// Recognised support/SLA tiers, ascending. `none` = no paid support.
pub const SUPPORT_TIERS: &[&str] = &["none", "business", "enterprise", "mission_critical"];
/// License commercial shape assigned when a token omits `license_class`.
pub const LICENSE_CLASS_SUBSCRIPTION: &str = "subscription";
/// Recognised license commercial shapes.
pub const LICENSE_CLASSES: &[&str] = &["subscription", "capacity", "site"];

/// Feature flag: access to the extended/long-term-support (LTS) release channel.
pub const FEATURE_SUPPORT_LTS: &str = "support.lts";
/// Feature flag: access to the FIPS-validated build channel.
pub const FEATURE_SUPPORT_FIPS: &str = "support.fips";
/// Feature flag: contractual CVE-response SLA (backported fixes within the
/// committed window).
pub const FEATURE_SUPPORT_CVE_RESPONSE: &str = "support.cve_response";

fn default_support_tier() -> String {
    SUPPORT_TIER_NONE.to_owned()
}

fn default_license_class() -> String {
    LICENSE_CLASS_SUBSCRIPTION.to_owned()
}

/// Whether `tier` is a recognised support tier.
pub fn is_known_support_tier(tier: &str) -> bool {
    SUPPORT_TIERS.contains(&tier)
}

/// Whether `class` is a recognised license commercial shape.
pub fn is_known_license_class(class: &str) -> bool {
    LICENSE_CLASSES.contains(&class)
}

/// Support-channel feature flags bundled with a support tier — the baseline a
/// tier includes before any à-la-carte add-on. `mission_critical` includes the
/// CVE-response SLA (an operational commitment deliverable today). The LTS and
/// FIPS release channels are **not** yet offered — no LTS branch or FIPS build
/// channel exists — so they are deliberately bundled into no tier; the
/// [`FEATURE_SUPPORT_LTS`] / [`FEATURE_SUPPORT_FIPS`] entitlements stay grantable
/// à la carte for when those channels ship. `business` and `none` bundle no
/// release-channel entitlements. This is a floor, not a ceiling.
pub fn support_features_for(tier: &str) -> Vec<String> {
    match tier {
        "mission_critical" => vec![FEATURE_SUPPORT_CVE_RESPONSE.into()],
        _ => vec![],
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Quotas {
    #[serde(default)]
    pub gateways: u64,
    #[serde(default)]
    pub plugins: u64,
    #[serde(default)]
    pub rps_per_gateway: u64,
    #[serde(default)]
    pub audit_retention_days: u64,
    #[serde(default)]
    pub workspaces: u64,
    #[serde(default)]
    pub users: u64,
    /// How many days of `instance_status_reports` to retain;
    /// retention is tiered by plan. `0` = use the CP's hardcoded
    /// default (30 days).
    #[serde(default)]
    pub status_report_retention_days: u64,
    /// How many hours of raw `tool_invocations` to retain. The
    /// rollup tables (hourly + daily) carry longer history. `0`
    /// = use the CP's hardcoded default (48 hours).
    #[serde(default)]
    pub tool_invocations_retention_hours: u64,
    /// Cap on tool calls per month per tenant. `0` = unlimited.
    /// Enforced at ingest time by counting rows in the rollup
    /// table over the trailing 30 days.
    #[serde(default)]
    pub tool_calls_per_month: u64,
    /// Cap on concurrently-registered reverse tunnels. `0`
    /// = unlimited. Enforced at tunnel-open against the count of live
    /// registered tunnels for the org (mirrors the gateway structural
    /// quota). The scarce resource is the relay registry slot, so this
    /// — not bandwidth — is the tunnel value metric.
    #[serde(default)]
    pub tunnels: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraceWindow {
    pub soft_warn_at: i64,
    pub hard_revert_at: i64,
}

impl LicenseClaims {
    /// Returns `true` iff the license is currently within its
    /// `nbf`/`exp` window. Does NOT verify signature; caller
    /// must do that separately.
    pub fn is_currently_valid(&self) -> bool {
        let now = Utc::now().timestamp();
        now >= self.nbf && now < self.exp
    }

    /// Returns the `exp` as a `DateTime<Utc>`.
    pub fn expires_at(&self) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(self.exp, 0).unwrap_or_else(Utc::now)
    }

    /// The synthetic Tier-0 envelope for a deployment with no license
    /// token: the `community` plan exactly as `plan_envelope` defines
    /// it. Never signed and never serialized as a JWT — a local
    /// stand-in so unlicensed deployments evaluate the same
    /// entitlement checks as licensed ones.
    pub fn community(aud: &str) -> Self {
        let (plugin_entitlements, quotas) = plan_envelope("community");
        let now = Utc::now().timestamp();
        Self {
            iss: "builtin:community".into(),
            sub: "tenant:00000000-0000-0000-0000-000000000000".into(),
            aud: vec![aud.to_string()],
            iat: now,
            // Tier-0 never expires; the envelope, not time, is the cap.
            exp: i64::MAX,
            nbf: 0,
            jti: "builtin-community".into(),
            lic_ver: 1,
            tenant_id: OrgId::from(uuid::Uuid::nil()),
            tenant_slug: "community".into(),
            plan: "community".into(),
            plugin_entitlements,
            features: features_for("community"),
            quotas,
            // Community has no residency guarantee and no region choice: both
            // are priced infrastructure, and the empty defaults mean "platform
            // default only".
            residency_domain: String::new(),
            allowed_regions: regions_for("community"),
            metadata: serde_json::Value::Null,
            grace: None,
            sovereign: false,
            airgap: false,
            support_tier: default_support_tier(),
            license_class: default_license_class(),
            issued_to: None,
        }
    }

    /// Returns `true` iff the given plugin id is covered by any
    /// entitlement glob.
    ///
    /// Canonical first-party plugin ids are reverse-DNS
    /// (`dev.mcpg.identity.saml`) while entitlement globs use the short
    /// namespace form (`identity.*`), so first-party ids are
    /// also matched with the `dev.mcpg.` prefix stripped. Third-party
    /// ids (`acme.policy.x`) match only their full form.
    pub fn entitled_for_plugin(&self, plugin_id: &str) -> bool {
        let mut builder = GlobSetBuilder::new();
        for pat in &self.plugin_entitlements {
            if let Ok(g) = Glob::new(pat) {
                builder.add(g);
            }
        }
        let Ok(set) = builder.build() else {
            return false;
        };
        set.is_match(plugin_id)
            || plugin_id
                .strip_prefix(FIRST_PARTY_ID_PREFIX)
                .is_some_and(|short| set.is_match(short))
    }

    /// Whether this tenant may publish into `region`.
    ///
    /// An empty `allowed_regions` means "the platform default only", which is
    /// expressed as an empty request region — a plan that says nothing about
    /// regions must not silently grant every region, or the entitlement would
    /// be unenforceable for exactly the tenants who never bought it.
    pub fn allows_region(&self, region: &str) -> bool {
        if self.allowed_regions.is_empty() {
            return region.trim().is_empty();
        }
        let mut builder = GlobSetBuilder::new();
        for pat in &self.allowed_regions {
            if let Ok(g) = Glob::new(pat) {
                builder.add(g);
            }
        }
        let Ok(set) = builder.build() else {
            // A malformed pattern must not widen the grant. Fail closed on
            // everything except the default region.
            return region.trim().is_empty();
        };
        // The default region is always permitted: a tenant that names no
        // region gets whatever the platform picks, which is what an
        // unrestricted publish already did.
        region.trim().is_empty() || set.is_match(region)
    }

    /// The compliance boundary this tenant belongs to, normalised. Empty in the
    /// claim means the platform default.
    pub fn residency(&self) -> &str {
        let r = self.residency_domain.trim();
        if r.is_empty() { "default" } else { r }
    }

    /// Returns `true` iff the named feature flag is enabled by
    /// this license.
    pub fn has_feature(&self, name: &str) -> bool {
        self.features.iter().any(|f| f == name)
    }

    /// The support/SLA tier this license carries (`none` when unset).
    pub fn support_tier(&self) -> &str {
        &self.support_tier
    }

    /// Whether this license entitles the LTS (extended-support) release channel.
    pub fn has_support_lts(&self) -> bool {
        self.has_feature(FEATURE_SUPPORT_LTS)
    }

    /// Whether this license entitles the FIPS-validated build channel.
    pub fn has_support_fips(&self) -> bool {
        self.has_feature(FEATURE_SUPPORT_FIPS)
    }

    /// Whether this license carries the contractual CVE-response SLA.
    pub fn has_support_cve_response(&self) -> bool {
        self.has_feature(FEATURE_SUPPORT_CVE_RESPONSE)
    }

    /// Tenant identity derived from `sub`. Returns the parsed
    /// UUID; falls back to `tenant_id` if parsing fails.
    pub fn tenant(&self) -> OrgId {
        self.tenant_id
    }

    /// All the audiences as a set, lower-cased.
    pub fn audiences(&self) -> BTreeSet<String> {
        self.aud.iter().map(|s| s.to_ascii_lowercase()).collect()
    }
}

/// Reverse-DNS prefix of first-party plugin ids. Entitlement globs and
/// feature gates address first-party plugins by their short namespace
/// (`identity.saml`), so matching strips this prefix.
pub const FIRST_PARTY_ID_PREFIX: &str = "dev.mcpg.";

/// The license feature a plugin additionally requires, beyond the
/// `plugin_entitlements` glob match — for premium plugins that live inside a
/// SHARED namespace whose free members any plan may install. The entitlement
/// glob admits the namespace; this feature gate makes the premium cut, enforced
/// at the CP plugin-set bind (`handlers::plugin_sets::upsert`). Returns `None`
/// for the (vast) majority of plugins that carry no feature gate. Accepts both
/// the canonical reverse-DNS id (`dev.mcpg.identity.saml`) and the short
/// namespaced form used in entitlement globs (`identity.saml`); the match arms
/// use the REAL reduced plugin ids (e.g. the DLP gate is `tool-gate.dlp`, not
/// `security.dlp`).
///
/// Only features that exist in the product belong here: gating a
/// nonexistent capability would refuse binds for nothing in return.
pub fn required_feature_for_plugin(plugin_id: &str) -> Option<&'static str> {
    let id = plugin_id
        .strip_prefix(FIRST_PARTY_ID_PREFIX)
        .unwrap_or(plugin_id);
    match id {
        // Each of these lives in a namespace a lower tier can already glob-bind
        // (identity.*, tool-gate.*, audit.*, credential.*), so the plan feature —
        // not the glob — is what withholds the premium capability.
        "identity.saml" => Some("sso.saml"),
        "identity.kerberos" => Some("sso.kerberos"),
        "tool-gate.dlp" => Some("dlp"),
        "tool-gate.field-crypto" => Some("field_crypto"),
        "audit.s3-worm" => Some("audit.worm"),
        // The Slack human-in-the-loop approval gate and the guardrails gate
        // reduce to these exact ids (neither matches `tool-gate.*`); the
        // envelope admits them by exact id and the feature makes the cut.
        "tool-gate-slack-approval" => Some("approvals.hitl"),
        "guardrails" => Some("guardrails"),
        // Dynamic-credential brokering (Vault, AWS STS, GCP, Azure, OAuth token
        // exchange) is one sold capability: every broker that mints short-lived
        // credentials on demand shares `secrets.dynamic`. The free credential
        // plugins (static, jwt-mint, oauth-client-credentials) stay ungated.
        "credential.vault-dynamic-db"
        | "credential.aws-sts"
        | "credential.gcp-impersonation"
        | "credential.azure-identity"
        | "credential.oauth-token-exchange"
        | "credential.oauth-id-jag" => Some("secrets.dynamic"),
        // Enterprise system connectors (sold as `backend.enterprise`). The
        // warehouse/analytics backends + basic telemetry stay Apache-2.0 — they're
        // adoption table-stakes; the enterprise-system connectors are where real
        // willingness-to-pay sits.
        "backend.grpc" | "backend.soap" | "backend.kafka" | "backend.mssql" | "backend.oracle"
        | "backend.ldap" => Some("backend.enterprise"),
        // Advanced identity providers (sold as `identity.advanced`).
        "identity.ldap" | "identity.paseto" | "identity.workload" => Some("identity.advanced"),
        _ => None,
    }
}

/// Namespaces holding no free plugins — a lower tier's envelope never
/// admits them, so membership alone marks a plugin as paid
/// (`plan_envelope` adds them only from `pro`/`team` upward).
pub const PAID_NAMESPACES: &[&str] = &["payment.", "policy.", "cluster.", "secret."];

/// Returns `true` iff `plugin_id` is a first-party plugin the
/// entitlement layer withholds from free plans — a feature-gated id or
/// a member of a paid-only namespace. Third-party ids (`acme.foo.bar`)
/// never match: their form reaches neither the feature table's exact
/// ids nor the paid namespaces.
pub fn is_entitlement_gated(plugin_id: &str) -> bool {
    let reduced = plugin_id
        .strip_prefix(FIRST_PARTY_ID_PREFIX)
        .unwrap_or(plugin_id);
    required_feature_for_plugin(plugin_id).is_some()
        || PAID_NAMESPACES.iter().any(|ns| reduced.starts_with(ns))
}

/// Why `plugin_id` may not run under `claims` — `None` means permitted.
/// Only entitlement-gated first-party plugins are ever refused; free and
/// third-party plugins always pass. The two failure shapes mirror the CP
/// plugin-set bind: the envelope glob must admit the id, and a
/// feature-gated plugin additionally needs its plan feature.
pub fn plugin_load_violation(claims: &LicenseClaims, plugin_id: &str) -> Option<LicenseError> {
    if !is_entitlement_gated(plugin_id) {
        return None;
    }
    if !claims.entitled_for_plugin(plugin_id) {
        return Some(LicenseError::PluginNotEntitled(plugin_id.to_string()));
    }
    if let Some(feature) = required_feature_for_plugin(plugin_id)
        && !claims.has_feature(feature)
    {
        return Some(LicenseError::FeatureNotLicensed {
            plugin: plugin_id.to_string(),
            feature: feature.to_string(),
        });
    }
    None
}

/// Plugin entitlement globs + quotas for a plan tier. The SINGLE source of
/// truth for every issuer: the federation's paid/offline licenses and the CP's
/// Tier-0 community license all take their envelope from here, so a plan means
/// the same thing regardless of who minted the token. Unknown plans get the
/// community envelope (deny-by-default for everything paid).
///
/// Globs are grounded in the real plugin catalog: each entry is either a real
/// reduced-id namespace (`identity.*` covers `dev.mcpg.identity.basic`) or the
/// exact reduced id of a plugin whose id has no namespace (`circuit-breaker`,
/// `webhook`). Several namespaces are SHARED free+premium: the free members
/// bind on any plan, while the premium members carry an ADDITIONAL feature
/// requirement (`required_feature_for_plugin` is the canonical list) enforced
/// at the CP plugin-set bind. The glob admits the namespace; the feature gate
/// makes the premium cut — so a free plugin is never paywalled by the
/// envelope. `payment.*` / `policy.*` / `cluster.*` / `secret.*` hold no free
/// members and are gated purely by tier.
/// Regions a plan may publish into.
///
/// Region choice is priced infrastructure — a cell in another region is other
/// hardware, often in another jurisdiction — so only plans that pay for
/// multi-region get to pick. An empty list means "the platform default region
/// only", which is what a caller who names no region already gets.
///
/// Issued into every licence so the entitlement travels with the token. A
/// deployment upgrading to region enforcement must roll the FEDERATION first:
/// the control plane's 15-minute refresh then installs licences carrying this
/// claim, and only after that does the CP's gate have anything to read.
/// Whether `plan` is the free tier.
///
/// The free tier is a static single instance: it gets no managed provisioning
/// beyond that one, and its instance-hours are never billed — compute is
/// priced per hour by type on paid tiers only. Both of those gates read this,
/// as does the control plane's provisioning check, so the answer is in one
/// place.
///
/// `community` is the vocabulary's own name for it. The other two matches are
/// deliberate and are not additional plan names: `""` is what an org with no
/// resolvable licence reads as, and an unlicensed org must not provision paid
/// infrastructure or accrue compute charges; `free` is issued by nothing today
/// but is the obvious name for a future trial tier, and reading it as paid is
/// the failure neither gate can afford.
pub fn is_free_plan(plan: &str) -> bool {
    matches!(plan, "community" | "free" | "")
}

pub fn regions_for(plan: &str) -> Vec<String> {
    match plan {
        // Multi-region is part of what these plans buy.
        "enterprise" | "sovereign" => vec!["*".into()],
        "team" | "org" => vec!["us-*".into(), "eu-*".into()],
        // Single-region plans: the platform picks.
        _ => Vec::new(),
    }
}

/// The compute type every plan includes at no charge.
///
/// Compute is billed only when a tenant opts UP from this: the included type
/// covers every running gateway a plan's quota allows, replicas included, and
/// costs nothing. Community may select nothing else (see the publish-path size
/// ceiling), so a free tenant is never billed for compute at all.
///
/// Shared by the control plane, which defaults a publish to this size, and the
/// federation, which skips it when metering instance-hours — two copies would
/// let a tenant be charged for the type they were told is free.
pub const INCLUDED_COMPUTE_SIZE: &str = "s";

pub fn plan_envelope(plan: &str) -> (Vec<String>, Quotas) {
    let core_globs = vec![
        "core.*".into(),
        "identity.*".into(),
        "transform.*".into(),
        "transport.*".into(),
        "cache.*".into(),
        "reliability.*".into(),
        "observability.*".into(),
        "metrics.*".into(),
        "log.*".into(),
        "watch.*".into(),
        "integration.*".into(),
        "storage.*".into(),
        "catalog.*".into(),
        "audit.*".into(),
        "tool-gate.*".into(),
        "credential.*".into(),
        // Free plugins whose reduced ids carry no namespace.
        "audit".into(),
        "call-logger".into(),
        "webhook".into(),
        "circuit-breaker".into(),
        "rate-limit".into(),
        "response-cache".into(),
        "ip-allowlist".into(),
        // Premium exact-id gates (outside `tool-gate.*`): admitted here, cut
        // by their `required_feature_for_plugin` feature.
        "tool-gate-slack-approval".into(),
        "guardrails".into(),
    ];

    match plan {
        "pro" => (
            [core_globs.clone(), vec!["payment.*".into()]].concat(),
            Quotas {
                gateways: 3,
                plugins: 100,
                rps_per_gateway: 200,
                audit_retention_days: 30,
                workspaces: 3,
                users: 5,
                status_report_retention_days: 30,
                tool_invocations_retention_hours: 48,
                tool_calls_per_month: 1_000_000,
                tunnels: 3,
            },
        ),
        "team" => (
            [
                core_globs.clone(),
                vec![
                    "payment.*".into(),
                    "policy.*".into(),
                    "cluster.*".into(),
                    "secret.*".into(),
                    // Backends are gated per-plugin by `required_feature_for_plugin`
                    // (e.g. `backend.warehouse`); the glob admits them so team's
                    // features make the premium cut. Free backends bypass the gate,
                    // so this only ever matters for the gated ones.
                    "backend.*".into(),
                ],
            ]
            .concat(),
            Quotas {
                gateways: 10,
                plugins: 300,
                rps_per_gateway: 1_000,
                audit_retention_days: 90,
                workspaces: 10,
                users: 25,
                status_report_retention_days: 90,
                tool_invocations_retention_hours: 96,
                tool_calls_per_month: 10_000_000,
                tunnels: 10,
            },
        ),
        "enterprise" => (
            vec!["*".into()],
            Quotas {
                // `0` = unlimited (structural quota checks treat 0 as no ceiling).
                gateways: 0,
                plugins: 0,
                rps_per_gateway: 100_000,
                audit_retention_days: 365 * 7,
                workspaces: 0,
                users: 0,
                status_report_retention_days: 365,
                tool_invocations_retention_hours: 168,
                tool_calls_per_month: 0,
                tunnels: 0,
            },
        ),
        // Default / community fallback — the metered free tier.
        _ => (
            core_globs,
            Quotas {
                gateways: 1,
                plugins: 25,
                rps_per_gateway: 50,
                audit_retention_days: 7,
                workspaces: 1,
                users: 2,
                status_report_retention_days: 7,
                tool_invocations_retention_hours: 24,
                tool_calls_per_month: 100_000,
                // The free wedge: one public dev tunnel (ngrok-for-MCP). Private
                // reverse-federation tunnels need the `tunnels.private` feature.
                tunnels: 1,
            },
        ),
    }
}

/// How a sold feature is actually withheld from a tenant who has not bought it.
///
/// Every feature any plan grants must appear in [`enforcement_of`]. The point
/// is not documentation — it is that adding a flag to [`features_for`] without
/// deciding how it is enforced fails a test, because a flag in a signed
/// licence is a promise and an ungated one is a promise we do not keep.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeatureEnforcement {
    /// Withheld at plugin load by [`required_feature_for_plugin`].
    PluginGate,
    /// Withheld because the plugins live in a [`PAID_NAMESPACES`] namespace a
    /// lower tier's envelope never admits. The flag is descriptive.
    PaidNamespace,
    /// Checked directly with `has_feature` at the named site.
    DirectCheck(&'static str),
    /// A deployment posture settled by contract and placement, with no runtime
    /// check to make.
    ContractPosture,
    /// Granted and enforced by NOTHING, with the reason. Every entry here is a
    /// gap between the price sheet and the code; keep the list shrinking.
    Unenforced(&'static str),
}

/// The enforcement site for a sold feature, or `None` if it is not sold.
pub fn enforcement_of(feature: &str) -> Option<FeatureEnforcement> {
    use FeatureEnforcement::*;
    Some(match feature {
        "sso.saml" | "sso.kerberos" | "dlp" | "field_crypto" | "guardrails" | "audit.worm"
        | "approvals.hitl" | "secrets.dynamic" | "backend.enterprise" | "identity.advanced" => {
            PluginGate
        }
        "clustering" | "policy.advanced" => PaidNamespace,
        "tunnels.private" | "tunnels.e2ee" => DirectCheck("control-plane handlers/tunnels.rs"),
        "payload_capture" => DirectCheck("control-plane metrics ingest"),
        "byoc" | "sovereign" => ContractPosture,
        "sso.oidc" => Unenforced("control-plane OIDC is core and available to every tier"),
        "audit.export" => {
            Unenforced("no dedicated export surface; the filtered audit list is ungated")
        }
        _ => return None,
    })
}

/// Feature flags granted by a plan tier — the companion to [`plan_envelope`]
/// and equally the single source of truth for every issuer. Unknown plans get
/// no features.
pub fn features_for(plan: &str) -> Vec<String> {
    // Team's feature set. Enterprise is a strict superset, so it reuses this and
    // appends the enterprise-only flags — keeping the two in lockstep.
    // Deliberately ABSENT: `scim`, `rbac.workspace`, `rbac.environment`. A
    // feature flag in a signed licence is a promise the platform can keep;
    // none of the three has an implementation to gate, so granting them
    // claimed a capability that does not exist. Role-based authorization IS
    // sold — as the `policy.*` plugins (Casbin/Cedar/OPA) at the gateway,
    // withheld from lower tiers by the paid-namespace rule.
    let team_features = || -> Vec<String> {
        vec![
            "sso.oidc".into(),
            "sso.saml".into(),
            "audit.export".into(),
            "clustering".into(),
            "policy.advanced".into(),
            "secrets.dynamic".into(),
            "approvals.hitl".into(),
            // Enterprise-system backend connectors (grpc/soap/kafka/mssql/oracle/
            // ldap) and advanced identity providers (identity ldap/paseto/workload).
            "backend.enterprise".into(),
            "identity.advanced".into(),
            // Reverse-federation tunnels: a `private` (federation-only)
            // tunnel + `tunnel://` upstream, so an org runs a gateway on its own
            // infra with its own secrets and federates it privately. Public dev
            // tunnels need no feature (governed by the `tunnels` quota alone); this
            // gates the private exposure. Team+ — the reason teams upgrade.
            "tunnels.private".into(),
        ]
    };

    match plan {
        "pro" => vec!["sso.oidc".into(), "audit.export".into()],
        "team" => team_features(),
        "enterprise" => [
            team_features(),
            vec![
                "sso.kerberos".into(),
                "byoc".into(),
                // The gateway gates full request/response capture on the
                // `payload_capture` feature; the WORM audit sink on `audit.worm`;
                // the DLP / field-crypto / guardrails gates on `dlp` /
                // `field_crypto` / `guardrails`.
                "payload_capture".into(),
                "dlp".into(),
                "field_crypto".into(),
                "guardrails".into(),
                "audit.worm".into(),
                "sovereign".into(),
                // End-to-end-encrypted tunnels (e2ee mode): the relay
                // splices ciphertext, mcpg-to-mcpg only. The sovereign posture.
                "tunnels.e2ee".into(),
            ],
        ]
        .concat(),
        _ => vec![],
    }
}

/// Verify a license JWT against a trusted Ed25519 public key.
///
/// Validates: signature, alg=`EdDSA`, audience contains
/// `expected_aud`, lic_ver ≤ `MAX_SUPPORTED_LIC_VER`, current
/// time within `nbf..exp`.
///
/// Returns the parsed claims on success.
pub fn verify_license(
    token: &str,
    trust_anchor: &VerifyingKey,
    expected_aud: &str,
) -> Result<LicenseClaims, LicenseError> {
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_audience(&[expected_aud]);
    validation.validate_nbf = true;
    validation.validate_exp = true;
    validation.leeway = 60;

    let key = DecodingKey::from_ed_der(trust_anchor.to_bytes().as_ref());

    let data = jsonwebtoken::decode::<LicenseClaims>(token, &key, &validation)
        .map_err(|e| LicenseError::Verification(e.to_string()))?;

    if data.claims.lic_ver > MAX_SUPPORTED_LIC_VER {
        return Err(LicenseError::UnsupportedVersion(data.claims.lic_ver));
    }
    Ok(data.claims)
}

pub const MAX_SUPPORTED_LIC_VER: u32 = 1;

#[derive(Debug, Error)]
pub enum LicenseError {
    /// Signature, expiry, not-before, or audience failure — jsonwebtoken's
    /// error text carries the specific cause.
    #[error("license verification failed: {0}")]
    Verification(String),

    #[error("unsupported license version {0} (max supported: 1)")]
    UnsupportedVersion(u32),

    #[error("plugin `{0}` is not entitled by this license")]
    PluginNotEntitled(String),

    #[error(
        "plugin `{plugin}` requires the `{feature}` plan feature, which this license does not grant"
    )]
    FeatureNotLicensed { plugin: String, feature: String },
}

/// Parse an Ed25519 verifying key from an SPKI PEM string — the
/// format `mcpg-license keygen --public-out` emits.
pub fn verifying_key_from_pem(pem: &str) -> Result<VerifyingKey, LicenseError> {
    use ed25519_dalek::pkcs8::DecodePublicKey;
    VerifyingKey::from_public_key_pem(pem).map_err(|e| {
        LicenseError::Verification(format!("not a valid Ed25519 SPKI PEM public key: {e}"))
    })
}

/// Verify just a raw signature (for non-JWT uses, e.g. license
/// manifest signing).
pub fn verify_signature(
    bytes: &[u8],
    sig: &Signature,
    pubkey: &VerifyingKey,
) -> Result<(), LicenseError> {
    use ed25519_dalek::Verifier;
    pubkey
        .verify(bytes, sig)
        .map_err(|e| LicenseError::Verification(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plan_that_names_no_regions_grants_only_the_default() {
        // The failure this guards: treating an absent entitlement as
        // unrestricted, which makes region choice unenforceable for exactly
        // the tenants who never bought it.
        let c = LicenseClaims::community("mcpg-cp");
        assert!(c.allows_region(""), "an unspecified region is always fine");
        assert!(!c.allows_region("eu-west-1"));
        assert!(!c.allows_region("us-east-1"));
    }

    #[test]
    fn allowed_regions_match_as_globs() {
        let mut c = LicenseClaims::community("mcpg-cp");
        c.allowed_regions = vec!["eu-*".into()];
        assert!(c.allows_region("eu-west-1"));
        assert!(c.allows_region("eu-central-1"));
        assert!(!c.allows_region("us-east-1"));
        // …and the default is still reachable.
        assert!(c.allows_region(""));
    }

    #[test]
    fn a_malformed_region_pattern_does_not_widen_the_grant() {
        let mut c = LicenseClaims::community("mcpg-cp");
        c.allowed_regions = vec!["eu-[".into()];
        assert!(!c.allows_region("eu-west-1"));
        assert!(c.allows_region(""));
    }

    #[test]
    fn residency_defaults_when_the_claim_is_absent() {
        let mut c = LicenseClaims::community("mcpg-cp");
        assert_eq!(c.residency(), "default");
        c.residency_domain = "  eu ".into();
        assert_eq!(c.residency(), "eu");
    }

    #[test]
    fn the_new_claims_deserialize_from_a_token_that_predates_them() {
        // Both fields are additive; a licence minted before they existed must
        // still verify rather than failing every tenant on it.
        let old = serde_json::json!({
            "iss": "https://auth.mcpg.dev", "sub": "tenant:x", "aud": ["mcpg-cp"],
            "iat": 0, "exp": 1, "nbf": 0, "jti": "j", "lic_ver": 1,
            "tenant_id": "00000000-0000-0000-0000-000000000000",
            "tenant_slug": "acme", "plan": "team",
            "plugin_entitlements": [], "features": [],
            "quotas": {"gateways": 1, "workspaces": 1, "members": 1,
                       "tool_calls_per_month": 1, "plugins": 1},
        });
        let c: LicenseClaims = serde_json::from_value(old).expect("older token must still parse");
        assert_eq!(c.residency(), "default");
        assert!(c.allowed_regions.is_empty());
    }

    use ed25519_dalek::SigningKey;
    use jsonwebtoken::{EncodingKey, Header};
    use rand::rngs::OsRng;

    fn sample_claims(exp_offset_secs: i64) -> LicenseClaims {
        let now = Utc::now().timestamp();
        LicenseClaims {
            iss: "https://auth.mcpg.dev".into(),
            sub: format!("tenant:{}", uuid::Uuid::nil()),
            aud: vec!["mcpg-cp".into(), "mcpg-gateway".into()],
            iat: now,
            exp: now + exp_offset_secs,
            nbf: now,
            jti: "lic_test".into(),
            lic_ver: 1,
            tenant_id: OrgId::from(uuid::Uuid::nil()),
            tenant_slug: "test".into(),
            plan: "team".into(),
            plugin_entitlements: vec!["core.*".into(), "policy.cedar".into(), "identity.*".into()],
            features: vec!["multi_workspace".into(), "audit_ledger".into()],
            quotas: Quotas {
                gateways: 50,
                plugins: 200,
                rps_per_gateway: 10000,
                audit_retention_days: 365,
                workspaces: 25,
                users: 200,
                status_report_retention_days: 90,
                tool_invocations_retention_hours: 168,
                tool_calls_per_month: 0,
                tunnels: 10,
            },
            residency_domain: String::new(),
            allowed_regions: Vec::new(),
            metadata: serde_json::Value::Null,
            grace: None,
            sovereign: false,
            airgap: false,
            support_tier: "none".into(),
            license_class: "subscription".into(),
            issued_to: None,
        }
    }

    #[test]
    fn entitlement_glob_matches() {
        let c = sample_claims(3600);
        assert!(c.entitled_for_plugin("core.foo"));
        assert!(c.entitled_for_plugin("identity.workload"));
        assert!(c.entitled_for_plugin("policy.cedar"));
        assert!(!c.entitled_for_plugin("policy.regulated-finance"));
        assert!(!c.entitled_for_plugin("audit.s3"));
    }

    #[test]
    fn tunnel_quota_scales_by_tier() {
        // Public dev tunnels for every tier (governed by the quota alone); the
        // concurrent count is the value metric. 0 = unlimited (enterprise).
        assert_eq!(plan_envelope("community").1.tunnels, 1);
        assert_eq!(plan_envelope("pro").1.tunnels, 3);
        assert_eq!(plan_envelope("team").1.tunnels, 10);
        assert_eq!(plan_envelope("enterprise").1.tunnels, 0);
        // Unknown plans fall through to the community envelope.
        assert_eq!(plan_envelope("bogus").1.tunnels, 1);
    }

    #[test]
    fn private_tunnels_are_gated_to_team_and_above() {
        // Reverse federation (private exposure) is the Team upsell.
        assert!(features_for("team").iter().any(|f| f == "tunnels.private"));
        assert!(
            features_for("enterprise")
                .iter()
                .any(|f| f == "tunnels.private")
        );
        assert!(!features_for("pro").iter().any(|f| f == "tunnels.private"));
        assert!(
            !features_for("community")
                .iter()
                .any(|f| f == "tunnels.private")
        );
    }

    #[test]
    fn e2ee_tunnels_are_enterprise_only() {
        assert!(
            features_for("enterprise")
                .iter()
                .any(|f| f == "tunnels.e2ee")
        );
        assert!(!features_for("team").iter().any(|f| f == "tunnels.e2ee"));
    }

    #[test]
    fn entitlement_matches_first_party_reverse_dns_ids() {
        let c = sample_claims(3600);
        // Canonical first-party ids match through their short namespace.
        assert!(c.entitled_for_plugin("dev.mcpg.identity.workload"));
        assert!(c.entitled_for_plugin("dev.mcpg.core.tool-gate"));
        assert!(c.entitled_for_plugin("dev.mcpg.policy.cedar"));
        // …but only what the namespace actually grants.
        assert!(!c.entitled_for_plugin("dev.mcpg.payment.acp"));
        assert!(!c.entitled_for_plugin("dev.mcpg.audit.s3"));
        // Third-party reverse-DNS ids do NOT ride the first-party stripping.
        assert!(!c.entitled_for_plugin("acme.identity.workload"));
    }

    #[test]
    fn feature_lookup() {
        let c = sample_claims(3600);
        assert!(c.has_feature("audit_ledger"));
        assert!(c.has_feature("multi_workspace"));
        assert!(!c.has_feature("sso"));
    }

    #[test]
    fn feature_gated_plugins_map_to_their_feature() {
        // Every premium plugin maps to its feature by BOTH the reverse-DNS id and
        // the short reduced form. The reduced ids are the plugins' real declared
        // namespaces (the DLP/field-crypto gates reduce to `tool-gate.*`, the
        // WORM sink to `audit.s3-worm`), not their source directory names.
        for (id, feature) in [
            ("identity.saml", "sso.saml"),
            ("identity.kerberos", "sso.kerberos"),
            ("tool-gate.dlp", "dlp"),
            ("tool-gate.field-crypto", "field_crypto"),
            ("audit.s3-worm", "audit.worm"),
            ("credential.vault-dynamic-db", "secrets.dynamic"),
            ("credential.aws-sts", "secrets.dynamic"),
            ("credential.gcp-impersonation", "secrets.dynamic"),
            ("credential.azure-identity", "secrets.dynamic"),
            ("credential.oauth-token-exchange", "secrets.dynamic"),
            ("credential.oauth-id-jag", "secrets.dynamic"),
            ("tool-gate-slack-approval", "approvals.hitl"),
            ("guardrails", "guardrails"),
            // Enterprise-system backend connectors + advanced identity providers.
            // (The warehouse backends, basic telemetry, and circuit-breaker stay
            // Apache-2.0 — asserted ungated below.)
            ("backend.grpc", "backend.enterprise"),
            ("backend.soap", "backend.enterprise"),
            ("backend.kafka", "backend.enterprise"),
            ("backend.mssql", "backend.enterprise"),
            ("backend.oracle", "backend.enterprise"),
            ("backend.ldap", "backend.enterprise"),
            ("identity.ldap", "identity.advanced"),
            ("identity.paseto", "identity.advanced"),
            ("identity.workload", "identity.advanced"),
        ] {
            assert_eq!(
                required_feature_for_plugin(id),
                Some(feature),
                "short id `{id}`"
            );
            assert_eq!(
                required_feature_for_plugin(&format!("dev.mcpg.{id}")),
                Some(feature),
                "reverse-DNS id `dev.mcpg.{id}`"
            );
        }

        // No gate for free plugins — including free members of the same shared
        // namespaces and third-party ids that merely end in a gated suffix.
        assert_eq!(required_feature_for_plugin("identity.basic"), None);
        assert_eq!(required_feature_for_plugin("dev.mcpg.identity.jwt"), None);
        // The warehouse/analytics backends, basic telemetry, and circuit-breaker
        // are Apache-2.0 table-stakes — never gated. A free backend (`backend.*`
        // member) is only ever admitted, never feature-gated.
        for free in [
            "dev.mcpg.backend.bigquery",
            "dev.mcpg.backend.clickhouse",
            "dev.mcpg.backend.duckdb",
            "dev.mcpg.backend.snowflake",
            "dev.mcpg.backend.dynamodb",
            "dev.mcpg.backend.elasticsearch",
            "dev.mcpg.backend.hana",
            "dev.mcpg.backend.http",
            "dev.mcpg.observability.prometheus",
            "dev.mcpg.observability.otlp",
            "dev.mcpg.audit",
            "dev.mcpg.circuit-breaker",
        ] {
            assert_eq!(
                required_feature_for_plugin(free),
                None,
                "{free} must stay free"
            );
            assert!(!is_entitlement_gated(free), "{free} must not be gated");
        }
        assert_eq!(
            required_feature_for_plugin("dev.mcpg.credential.static"),
            None
        );
        assert_eq!(
            required_feature_for_plugin("dev.mcpg.credential.jwt-mint"),
            None
        );
        assert_eq!(
            required_feature_for_plugin("dev.mcpg.credential.oauth-client-credentials"),
            None
        );
        assert_eq!(
            required_feature_for_plugin("dev.mcpg.tool-gate.schema"),
            None
        );
        assert_eq!(required_feature_for_plugin("dev.mcpg.ip-allowlist"), None);
        assert_eq!(required_feature_for_plugin("acme.identity.saml"), None);
        assert_eq!(required_feature_for_plugin("core.tool-gate"), None);
    }

    #[test]
    fn round_trip_signed_license_verifies() {
        use ed25519_dalek::pkcs8::EncodePrivateKey;

        let signing_key = SigningKey::generate(&mut OsRng);
        let pubkey = signing_key.verifying_key();
        let claims = sample_claims(3600);

        // Sign claims as a JWT
        let header = Header::new(Algorithm::EdDSA);
        let der_pkcs8 = signing_key.to_pkcs8_der().expect("pkcs8 encode");
        let enc_key = EncodingKey::from_ed_der(der_pkcs8.as_bytes());
        let token = jsonwebtoken::encode(&header, &claims, &enc_key).expect("encode");

        // Verify
        let verified = verify_license(&token, &pubkey, "mcpg-cp").expect("verify");
        assert_eq!(verified.tenant_slug, "test");
        assert_eq!(verified.plan, "team");
    }

    #[test]
    fn entitlement_gate_covers_exactly_the_paid_surface() {
        // Feature-gated inside a free namespace.
        assert!(is_entitlement_gated("dev.mcpg.identity.saml"));
        // Paid-namespace members, both id forms.
        assert!(is_entitlement_gated("dev.mcpg.payment.ucp"));
        assert!(is_entitlement_gated("cluster.redis"));
        // Free first-party and third-party ids pass untouched.
        assert!(!is_entitlement_gated("dev.mcpg.backend.http"));
        assert!(!is_entitlement_gated("dev.mcpg.identity.basic"));
        assert!(!is_entitlement_gated("acme.payment.custom"));
    }

    #[test]
    fn load_violation_mirrors_the_bind_gate() {
        let community = LicenseClaims::community("mcpg-gateway");
        assert!(plugin_load_violation(&community, "dev.mcpg.backend.http").is_none());
        assert!(plugin_load_violation(&community, "acme.policy.custom").is_none());
        assert!(matches!(
            plugin_load_violation(&community, "dev.mcpg.payment.ucp"),
            Some(LicenseError::PluginNotEntitled(_))
        ));
        // identity.* is glob-admitted on community; the feature makes the cut.
        assert!(matches!(
            plugin_load_violation(&community, "dev.mcpg.identity.saml"),
            Some(LicenseError::FeatureNotLicensed { .. })
        ));

        let mut team = LicenseClaims::community("mcpg-gateway");
        let (entitlements, quotas) = plan_envelope("team");
        team.plugin_entitlements = entitlements;
        team.quotas = quotas;
        team.features = features_for("team");
        team.plan = "team".into();
        assert!(plugin_load_violation(&team, "dev.mcpg.identity.saml").is_none());
        assert!(plugin_load_violation(&team, "dev.mcpg.cluster.redis").is_none());
        // Kerberos needs `sso.kerberos`, an enterprise-only feature.
        assert!(plugin_load_violation(&team, "dev.mcpg.identity.kerberos").is_some());
    }

    #[test]
    fn support_tier_baselines_bundle_only_deliverable_channels() {
        assert!(support_features_for("none").is_empty());
        assert!(support_features_for("business").is_empty());
        // LTS/FIPS are not offered yet → bundled into no tier, including enterprise.
        assert!(support_features_for("enterprise").is_empty());
        // mission_critical bundles the CVE-response SLA and nothing else.
        assert_eq!(
            support_features_for("mission_critical"),
            vec![FEATURE_SUPPORT_CVE_RESPONSE]
        );
        let mc = support_features_for("mission_critical");
        assert!(!mc.contains(&FEATURE_SUPPORT_LTS.to_string()));
        assert!(!mc.contains(&FEATURE_SUPPORT_FIPS.to_string()));
        // An unknown tier grants nothing (deny-by-default), like `plan_envelope`.
        assert!(support_features_for("platinum").is_empty());
    }

    #[test]
    fn support_and_class_allowlists() {
        assert!(is_known_support_tier("mission_critical"));
        assert!(!is_known_support_tier("gold"));
        assert!(is_known_license_class("site"));
        assert!(!is_known_license_class("perpetual"));
    }

    #[test]
    fn support_accessors_read_the_feature_flags() {
        // mission_critical baseline grants CVE-response but not the (unoffered)
        // LTS/FIPS channels.
        let mut c = sample_claims(3600);
        c.support_tier = "mission_critical".into();
        c.features.extend(support_features_for("mission_critical"));
        assert_eq!(c.support_tier(), "mission_critical");
        assert!(c.has_support_cve_response());
        assert!(!c.has_support_lts());
        assert!(!c.has_support_fips());

        // The LTS/FIPS accessors still read their flags when granted à la carte.
        c.features.push(FEATURE_SUPPORT_LTS.into());
        c.features.push(FEATURE_SUPPORT_FIPS.into());
        assert!(c.has_support_lts());
        assert!(c.has_support_fips());

        let base = sample_claims(3600);
        assert_eq!(base.support_tier(), "none");
        assert!(!base.has_support_cve_response());
    }

    #[test]
    fn old_tokens_without_support_fields_deserialize_to_defaults() {
        // A token minted before `support_tier` / `license_class` existed carries
        // neither field. serde defaults must fill them so verification of an
        // in-the-wild older token never fails on a missing field.
        let mut json = serde_json::to_value(sample_claims(3600)).unwrap();
        let obj = json.as_object_mut().unwrap();
        obj.remove("support_tier");
        obj.remove("license_class");
        let parsed: LicenseClaims = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.support_tier, "none");
        assert_eq!(parsed.license_class, "subscription");
    }
}

#[cfg(test)]
mod feature_enforcement_guard {
    use super::*;

    /// Every feature any plan grants must declare how it is enforced.
    ///
    /// This is the guard against the drift that let `scim`, `rbac.workspace`
    /// and `rbac.environment` be sold with no implementation behind them:
    /// adding a flag to `features_for` without deciding how it is withheld now
    /// fails here rather than reaching a price sheet.
    #[test]
    fn every_sold_feature_declares_its_enforcement() {
        let mut missing = Vec::new();
        for plan in ["community", "pro", "team", "enterprise"] {
            for f in features_for(plan) {
                if enforcement_of(&f).is_none() {
                    missing.push(format!("{plan}:{f}"));
                }
            }
        }
        assert!(
            missing.is_empty(),
            "these features are granted with no declared enforcement — decide how each is \
             withheld, or stop granting it: {missing:?}"
        );
    }

    /// The known gaps, pinned. Shrinking this list is progress; growing it
    /// silently is the failure this whole guard exists to prevent, so a new
    /// entry has to be added here deliberately.
    #[test]
    fn the_unenforced_set_is_exactly_what_we_expect() {
        let mut unenforced: Vec<String> = ["community", "pro", "team", "enterprise"]
            .iter()
            .flat_map(|p| features_for(p))
            .filter(|f| matches!(enforcement_of(f), Some(FeatureEnforcement::Unenforced(_))))
            .collect();
        unenforced.sort();
        unenforced.dedup();
        assert_eq!(
            unenforced,
            vec!["audit.export".to_string(), "sso.oidc".to_string()],
            "the set of sold-but-ungated features changed"
        );
    }

    /// A feature we do not sell must not claim an enforcement site — that
    /// would make the registry look complete while gating nothing.
    #[test]
    fn features_we_removed_are_not_in_the_registry() {
        for f in ["scim", "rbac.workspace", "rbac.environment"] {
            assert!(
                enforcement_of(f).is_none(),
                "`{f}` is not sold and must not appear in the enforcement registry"
            );
        }
    }

    /// Anything claiming a direct check must name where, or the registry is
    /// unverifiable prose.
    #[test]
    fn direct_checks_name_their_site() {
        for plan in ["pro", "team", "enterprise"] {
            for f in features_for(plan) {
                if let Some(FeatureEnforcement::DirectCheck(site)) = enforcement_of(&f) {
                    assert!(
                        !site.trim().is_empty(),
                        "`{f}` claims a direct check with no site"
                    );
                }
            }
        }
    }
}
