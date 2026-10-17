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

    /// Set by the federation while a renewal is unpaid and the plan is still
    /// issued: when the first payment failed and when the plan reverts.
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

    /// The licence is for non-production use only (development, testing,
    /// evaluation, staging). Every licence a staging issuer key signs carries
    /// it; a deployment running under it shows the marker in its logs, status
    /// and metrics.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub non_production: bool,
}

/// Audience of every licence a control plane accepts.
pub const AUDIENCE_CP: &str = "mcpg-cp";
/// Audience of a self-host licence a gateway accepts from its own `license:`
/// block.
pub const AUDIENCE_GATEWAY: &str = "mcpg-gateway";
/// Audience of a licence the managed platform delivers to a gateway. A cloud
/// licence names this and not [`AUDIENCE_GATEWAY`], so it is never a valid
/// self-host gateway licence.
pub const AUDIENCE_GATEWAY_MANAGED: &str = "mcpg-gateway-managed";

pub use crate::trust;
pub use crate::trust::{
    IssuerRole, KeyEnvironment, LICENSE_JWT_TYP, TrustPolicy, VendorLicense, thumbprint_kid,
    verify_vendor_license,
};

/// Days before `exp` from which a deployment warns that its licence expires.
pub const EXPIRY_WARNING_DAYS: i64 = 30;
/// Days after `exp` during which an expired self-host licence still grants
/// its plan, with warnings.
pub const EXPIRY_GRACE_DAYS: i64 = 14;
/// Days after `exp` during which an mcpg.cloud licence still grants its plan.
/// The platform re-issues a cloud licence before it expires, so an expired one
/// means its refresh is failing; a revoked one is replaced at once instead.
pub const CLOUD_REFRESH_GRACE_DAYS: i64 = 7;

/// Days after `exp` a licence signed by a key of `role` keeps its plan.
pub fn expiry_grace_days(role: IssuerRole) -> i64 {
    match role {
        IssuerRole::SelfHost => EXPIRY_GRACE_DAYS,
        IssuerRole::Cloud => CLOUD_REFRESH_GRACE_DAYS,
        // No licence policy accepts a platform key's signature.
        IssuerRole::Platform => 0,
    }
}

/// Where a licence stands against its expiry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LicenseTerm {
    /// More than [`EXPIRY_WARNING_DAYS`] from `exp`.
    Current,
    /// Within [`EXPIRY_WARNING_DAYS`] of `exp`.
    ExpiringSoon,
    /// Past `exp`, within its grace period ([`expiry_grace_days`]): the plan
    /// still holds.
    Grace,
    /// Past the grace period: the licence grants nothing.
    Lapsed,
}

impl LicenseTerm {
    /// The term of a self-host licence: [`EXPIRY_GRACE_DAYS`] of grace.
    pub fn of(exp: i64, now: i64) -> Self {
        Self::with_grace(exp, now, EXPIRY_GRACE_DAYS)
    }

    /// The term of a licence that keeps its plan `grace_days` past `exp`.
    pub fn with_grace(exp: i64, now: i64, grace_days: i64) -> Self {
        const DAY: i64 = 86_400;
        if now >= grace_ends_after(exp, grace_days) {
            LicenseTerm::Lapsed
        } else if now >= exp {
            LicenseTerm::Grace
        } else if now >= exp.saturating_sub(EXPIRY_WARNING_DAYS * DAY) {
            LicenseTerm::ExpiringSoon
        } else {
            LicenseTerm::Current
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            LicenseTerm::Current => "current",
            LicenseTerm::ExpiringSoon => "expiring",
            LicenseTerm::Grace => "grace",
            LicenseTerm::Lapsed => "lapsed",
        }
    }
}

/// When the grace period of a self-host licence expiring at `exp` ends.
pub fn grace_ends_at(exp: i64) -> i64 {
    grace_ends_after(exp, EXPIRY_GRACE_DAYS)
}

/// When a grace period of `grace_days` past `exp` ends.
pub fn grace_ends_after(exp: i64, grace_days: i64) -> i64 {
    exp.saturating_add(grace_days.saturating_mul(86_400))
}

/// Days a managed org keeps what it runs after it loses a paid plan — a
/// downgrade, a cancellation, a suspension, or an unpaid renewal, whose days
/// count from its first failed payment. New work is judged by the plan left at
/// once; what already runs stays until the grace ends.
pub const PLAN_LOSS_GRACE_DAYS: i64 = 7;

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
    /// Tool calls included per month per tenant. `0` = unlimited.
    /// Counted over the UTC calendar month; on mcpg.cloud a paid plan is
    /// served past it on packs and pay-as-you-go up to its spend cap.
    #[serde(default)]
    pub tool_calls_per_month: u64,
    /// Cap on concurrently-registered reverse tunnels. `0`
    /// = unlimited. Enforced at tunnel-open against the count of live
    /// registered tunnels for the org (mirrors the gateway structural
    /// quota). The scarce resource is the relay registry slot, so this
    /// — not bandwidth — is the tunnel value metric.
    #[serde(default)]
    pub tunnels: u64,
    /// Reverse-tunnel bytes relayed per calendar month (UTC) at no charge.
    /// `0` = unlimited. A paid plan pays for the bytes above it; the free plan
    /// is throttled past it, never stopped and never billed. `None` in a
    /// licence or plan snapshot issued before this axis existed; read it
    /// through [`Quotas::tunnel_bytes_for`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tunnel_bytes_per_month: Option<u64>,
    /// Managed-instance hours included per calendar month (UTC), counted in
    /// s-equivalents (see [`COMPUTE_WEIGHTS`]). `0` = unlimited. A paid plan
    /// pays for the hours above it; the free plan is never charged. `None` in
    /// a licence or plan snapshot issued before this axis existed; read it
    /// through [`Quotas::included_compute_hours_for`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub included_compute_hours_per_month: Option<u64>,
    /// Cap on live MCP Events readers on each gateway: webhook subscriptions,
    /// poll leases and open streams, plus the upstream subscriptions the
    /// gateway holds for imported event types. `0` = unlimited. `None` in a
    /// licence issued before this axis existed; read it through
    /// [`Quotas::event_subscriptions_for`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_subscriptions: Option<u64>,
    /// MCP Events deliveries included per calendar month (UTC), in every
    /// mode. `0` = unlimited. The free plan's deliveries hold once the
    /// month's are used; on mcpg.cloud a paid plan is served past it
    /// pay-as-you-go up to its spend cap. `None` in a licence issued before
    /// this axis existed; read it through [`Quotas::events_delivered_for`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events_delivered_per_month: Option<u64>,
    /// MCP Events occurrences taken into event logs per calendar month
    /// (UTC), from every source. `0` = unlimited. Sources are held once the
    /// month's are used. `None` in a licence issued before this axis existed;
    /// read it through [`Quotas::events_ingested_for`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events_ingested_per_month: Option<u64>,
    /// Cap on the MCP Events types one gateway serves, declared and imported.
    /// `0` = unlimited. Read it through [`Quotas::event_types_for`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_types: Option<u64>,
    /// Longest an event log keeps an occurrence, in milliseconds. `0` =
    /// unlimited. Read it through [`Quotas::event_retention_ms_for`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_retention_ms: Option<u64>,
    /// Most occurrences one event log keeps. `0` = unlimited. Read it
    /// through [`Quotas::event_retention_events_for`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_retention_events: Option<u64>,
    /// Most bytes one event log keeps. `0` = unlimited. Read it through
    /// [`Quotas::event_retention_bytes_for`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_retention_bytes: Option<u64>,
    /// Longest a webhook delivery is retried, in milliseconds. `0` =
    /// unlimited. Read it through [`Quotas::event_retry_window_ms_for`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_retry_window_ms: Option<u64>,
}

impl Quotas {
    /// The monthly tunnel-byte allowance of `plan` under these quotas: the
    /// value they carry, else the plan's compiled one. `0` = unlimited.
    pub fn tunnel_bytes_for(&self, plan: &str) -> u64 {
        self.tunnel_bytes_per_month
            .or_else(|| plan_envelope(plan).1.tunnel_bytes_per_month)
            .unwrap_or(0)
    }

    /// The monthly included compute of `plan` under these quotas, in
    /// s-equivalent instance-hours: the value they carry, else the plan's
    /// compiled one. `0` = unlimited.
    pub fn included_compute_hours_for(&self, plan: &str) -> u64 {
        self.included_compute_hours_per_month
            .or_else(|| plan_envelope(plan).1.included_compute_hours_per_month)
            .unwrap_or(0)
    }

    /// The live event reader cap of `plan` under these quotas: the value
    /// they carry, else the plan's compiled one. `0` = unlimited.
    pub fn event_subscriptions_for(&self, plan: &str) -> u64 {
        self.event_subscriptions
            .or_else(|| plan_envelope(plan).1.event_subscriptions)
            .unwrap_or(0)
    }

    /// The monthly MCP Events delivery allowance of `plan` under these
    /// quotas: the value they carry, else the plan's compiled one. `0` =
    /// unlimited.
    pub fn events_delivered_for(&self, plan: &str) -> u64 {
        self.events_delivered_per_month
            .or_else(|| plan_envelope(plan).1.events_delivered_per_month)
            .unwrap_or(0)
    }

    /// The monthly MCP Events ingest allowance of `plan` under these
    /// quotas: the value they carry, else the plan's compiled one. `0` =
    /// unlimited.
    pub fn events_ingested_for(&self, plan: &str) -> u64 {
        self.events_ingested_per_month
            .or_else(|| plan_envelope(plan).1.events_ingested_per_month)
            .unwrap_or(0)
    }

    /// The event type cap of `plan` under these quotas. `0` = unlimited.
    pub fn event_types_for(&self, plan: &str) -> u64 {
        self.event_types
            .or_else(|| plan_envelope(plan).1.event_types)
            .unwrap_or(0)
    }

    /// The event retention age cap of `plan` under these quotas, in
    /// milliseconds. `0` = unlimited.
    pub fn event_retention_ms_for(&self, plan: &str) -> u64 {
        self.event_retention_ms
            .or_else(|| plan_envelope(plan).1.event_retention_ms)
            .unwrap_or(0)
    }

    /// The event retention count cap of `plan` under these quotas. `0` =
    /// unlimited.
    pub fn event_retention_events_for(&self, plan: &str) -> u64 {
        self.event_retention_events
            .or_else(|| plan_envelope(plan).1.event_retention_events)
            .unwrap_or(0)
    }

    /// The event retention byte cap of `plan` under these quotas. `0` =
    /// unlimited.
    pub fn event_retention_bytes_for(&self, plan: &str) -> u64 {
        self.event_retention_bytes
            .or_else(|| plan_envelope(plan).1.event_retention_bytes)
            .unwrap_or(0)
    }

    /// The webhook retry window cap of `plan` under these quotas, in
    /// milliseconds. `0` = unlimited.
    pub fn event_retry_window_ms_for(&self, plan: &str) -> u64 {
        self.event_retry_window_ms
            .or_else(|| plan_envelope(plan).1.event_retry_window_ms)
            .unwrap_or(0)
    }

    /// Lift every MCP Events cap: each event axis becomes `0`, unlimited.
    pub fn clear_event_caps(&mut self) {
        self.event_subscriptions = Some(0);
        self.events_delivered_per_month = Some(0);
        self.events_ingested_per_month = Some(0);
        self.event_types = Some(0);
        self.event_retention_ms = Some(0);
        self.event_retention_events = Some(0);
        self.event_retention_bytes = Some(0);
        self.event_retry_window_ms = Some(0);
    }

    /// Take every MCP Events cap from `from`, keeping the other axes.
    pub fn copy_event_caps(&mut self, from: &Quotas) {
        self.event_subscriptions = from.event_subscriptions;
        self.events_delivered_per_month = from.events_delivered_per_month;
        self.events_ingested_per_month = from.events_ingested_per_month;
        self.event_types = from.event_types;
        self.event_retention_ms = from.event_retention_ms;
        self.event_retention_events = from.event_retention_events;
        self.event_retention_bytes = from.event_retention_bytes;
        self.event_retry_window_ms = from.event_retry_window_ms;
    }

    /// These quotas with every plan-backed axis resolved to the value in
    /// force for `plan`, so a reader that does not know the fallbacks sees
    /// what is enforced.
    pub fn resolved_for(&self, plan: &str) -> Quotas {
        Quotas {
            tunnel_bytes_per_month: Some(self.tunnel_bytes_for(plan)),
            included_compute_hours_per_month: Some(self.included_compute_hours_for(plan)),
            event_subscriptions: Some(self.event_subscriptions_for(plan)),
            events_delivered_per_month: Some(self.events_delivered_for(plan)),
            events_ingested_per_month: Some(self.events_ingested_for(plan)),
            event_types: Some(self.event_types_for(plan)),
            event_retention_ms: Some(self.event_retention_ms_for(plan)),
            event_retention_events: Some(self.event_retention_events_for(plan)),
            event_retention_bytes: Some(self.event_retention_bytes_for(plan)),
            event_retry_window_ms: Some(self.event_retry_window_ms_for(plan)),
            ..self.clone()
        }
    }
}

/// The days a paid licence is still issued while its renewal is unpaid, in
/// unix seconds: from the first failed payment (`soft_warn_at`) to the moment
/// the plan reverts (`hard_revert_at`). A control plane anchors the plan-loss
/// grace here rather than at the later moment the plan drops.
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
            non_production: false,
        }
    }

    /// Where this licence stands against its expiry at `now` (unix seconds).
    pub fn term(&self, now: i64) -> LicenseTerm {
        LicenseTerm::of(self.exp, now)
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
/// (`plan_envelope` admits them only from `pro` upward, and `cluster.`
/// only through enterprise's `*`).
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

/// Licence feature the mcpg.cloud federation adds to the managed licence of a
/// plan that grants `clustering` but whose entitlements leave out the
/// `cluster.*` plugins: it admits [`PLATFORM_COORDINATOR_PLUGIN`], which the
/// platform itself adds to a multi-replica gateway. It is not a plan feature:
/// no plan grants it, the self-host issuer never sets it, and a tenant's own
/// publish of the plugin is still checked against the plan.
pub const FEATURE_PLATFORM_COORDINATION: &str = "platform.cluster_coordination";

/// The coordinator the managed platform adds to a multi-replica gateway.
pub const PLATFORM_COORDINATOR_PLUGIN: &str = "dev.mcpg.cluster.nats";

/// Whether `claims` admit `plugin_id` as the coordinator the platform adds.
pub fn admits_platform_coordinator(claims: &LicenseClaims, plugin_id: &str) -> bool {
    plugin_id == PLATFORM_COORDINATOR_PLUGIN && claims.has_feature(FEATURE_PLATFORM_COORDINATION)
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

/// The default compute type: a publish that names no size gets it, and it is
/// the only one the free plan may select (see the publish-path size ceiling).
///
/// The free plan is never charged for compute. A paid plan pays for the
/// instance-hours above its included compute, counted in s-equivalents.
pub const INCLUDED_COMPUTE_SIZE: &str = "s";

/// Every compute type a managed instance runs as, smallest first. Each one is
/// a billed dimension on paid plans, so the federation needs a metered price
/// for every entry. A plan's included compute covers the types in this order.
pub const COMPUTE_SIZES: [&str; 4] = ["s", "m", "l", "xl"];

/// How many s-equivalent hours one instance-hour of each compute type counts
/// for, in [`COMPUTE_SIZES`] order.
pub const COMPUTE_WEIGHTS: [(&str, u64); 4] = [("s", 1), ("m", 2), ("l", 4), ("xl", 8)];

/// The s-equivalent weight of a compute type; `None` for an unknown type.
pub fn s_equivalent_weight(size: &str) -> Option<u64> {
    COMPUTE_WEIGHTS
        .iter()
        .find(|(s, _)| *s == size)
        .map(|(_, w)| *w)
}

/// One gibibyte, the unit tunnel-byte allowances are set in.
const GIB: u64 = 1 << 30;
/// The hours of the longest month, the unit included compute is set in: one
/// always-on gateway on `s` for a whole month.
const MONTH_HOURS: u64 = 31 * 24;
/// One mebibyte, the unit event-log byte caps are set in.
const MIB: u64 = 1 << 20;
/// One minute and one day in milliseconds, the units event time caps are
/// set in.
const MINUTE_MS: u64 = 60_000;
const DAY_MS: u64 = 24 * 60 * MINUTE_MS;

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
                tunnel_bytes_per_month: Some(10 * GIB),
                included_compute_hours_per_month: Some(MONTH_HOURS),
                event_subscriptions: Some(100),
                events_delivered_per_month: Some(1_000_000),
                events_ingested_per_month: Some(1_000_000),
                event_types: Some(100),
                event_retention_ms: Some(7 * DAY_MS),
                event_retention_events: Some(100_000),
                event_retention_bytes: Some(64 * MIB),
                event_retry_window_ms: Some(60 * MINUTE_MS),
            },
        ),
        "team" => (
            [
                core_globs.clone(),
                // No `cluster.*`: running more than one replica is an
                // Enterprise feature (`clustering`), self-hosted or managed.
                vec![
                    "payment.*".into(),
                    "policy.*".into(),
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
                tunnel_bytes_per_month: Some(100 * GIB),
                included_compute_hours_per_month: Some(3 * MONTH_HOURS),
                event_subscriptions: Some(1_000),
                events_delivered_per_month: Some(10_000_000),
                events_ingested_per_month: Some(10_000_000),
                event_types: Some(1_000),
                event_retention_ms: Some(30 * DAY_MS),
                event_retention_events: Some(1_000_000),
                event_retention_bytes: Some(256 * MIB),
                event_retry_window_ms: Some(6 * 60 * MINUTE_MS),
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
                tunnel_bytes_per_month: Some(0),
                // Unlimited unless a contract sets a value.
                included_compute_hours_per_month: Some(0),
                event_subscriptions: Some(0),
                events_delivered_per_month: Some(0),
                events_ingested_per_month: Some(0),
                event_types: Some(0),
                event_retention_ms: Some(0),
                event_retention_events: Some(0),
                event_retention_bytes: Some(0),
                event_retry_window_ms: Some(0),
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
                tunnel_bytes_per_month: Some(5 * GIB),
                // Never charged: it only prorates a free stretch of a month
                // that ends on a paid plan.
                included_compute_hours_per_month: Some(MONTH_HOURS),
                event_subscriptions: Some(10),
                events_delivered_per_month: Some(10_000),
                events_ingested_per_month: Some(10_000),
                event_types: Some(10),
                event_retention_ms: Some(DAY_MS),
                event_retention_events: Some(1_000),
                event_retention_bytes: Some(MIB),
                event_retry_window_ms: Some(5 * MINUTE_MS),
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
        FEATURE_CLUSTERING | "policy.advanced" => PaidNamespace,
        "tunnels.private" | "tunnels.e2ee" => DirectCheck("control-plane handlers/tunnels.rs"),
        FEATURE_INTERACTIVE_LOGIN | FEATURE_DPOP | FEATURE_RICH_AUTHORIZATION => DirectCheck(
            "gateway license_gate.rs (boot and reload of every gateway, against its own \
             licence or the one the platform delivers) and control-plane \
             publish_guard::check_config_entitlements (managed-cloud publishes)",
        ),
        "plugins.custom" => DirectCheck(
            "control-plane publish_guard::check_config_entitlements (plugin sources, registry \
             settings, trusted keys) and target_validate PluginPolicy (managed-cloud publishes)",
        ),
        "payload_capture" => DirectCheck("control-plane metrics ingest"),
        FEATURE_EVENTS_WEBHOOKS => DirectCheck(
            "gateway license_gate.rs (boot and reload; an attached gateway whose delivered \
             licence stops covering it stops delivering) and control-plane \
             publish_guard::check_config_entitlements (managed-cloud publishes)",
        ),
        FEATURE_SSO_ENTERPRISE => DirectCheck("control-plane handlers/sso.rs"),
        FEATURE_ISOLATION_DEDICATED => {
            DirectCheck("control-plane handlers/gateways.rs (managed-cloud publishes)")
        }
        FEATURE_HYBRID_GATEWAYS => DirectCheck(
            "control-plane handlers/enrollment.rs and grpc.rs Register (a self-registered \
             gateway enrolling into the managed service)",
        ),
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
            FEATURE_EVENTS_WEBHOOKS.into(),
            "sso.oidc".into(),
            "sso.saml".into(),
            FEATURE_SSO_ENTERPRISE.into(),
            "audit.export".into(),
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
        "community" | "free" => vec![FEATURE_EVENTS_WEBHOOKS.into()],
        "pro" => vec![
            FEATURE_EVENTS_WEBHOOKS.into(),
            "sso.oidc".into(),
            "audit.export".into(),
        ],
        "team" => team_features(),
        "enterprise" => [
            team_features(),
            vec![
                FEATURE_CLUSTERING.into(),
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
                // Reference plugins the customer publishes themselves, from
                // their own registry, rather than only first-party ones.
                "plugins.custom".into(),
                "sovereign".into(),
                // End-to-end-encrypted tunnels (e2ee mode): the relay
                // splices ciphertext, mcpg-to-mcpg only. The sovereign posture.
                "tunnels.e2ee".into(),
                FEATURE_INTERACTIVE_LOGIN.into(),
                FEATURE_DPOP.into(),
                FEATURE_RICH_AUTHORIZATION.into(),
                FEATURE_ISOLATION_DEDICATED.into(),
                FEATURE_HYBRID_GATEWAYS.into(),
            ],
        ]
        .concat(),
        _ => vec![],
    }
}

/// Feature name gating a tenant's own plugins (see [`features_for`]).
pub const FEATURE_CUSTOM_PLUGINS: &str = "plugins.custom";

/// Feature name gating MCP Events webhook delivery: an
/// `mcp.configurations.events` block that is enabled with its `webhook`
/// delivery on. Every plan, the community tier included; withheld, the
/// gateway refuses the config, or on an attached gateway stops delivering.
pub const FEATURE_EVENTS_WEBHOOKS: &str = "events.webhooks";

/// Feature name gating a dedicated isolation tier on the managed service: a
/// publish placed on cells reserved for the org rather than the shared pool.
/// Enterprise only.
pub const FEATURE_ISOLATION_DEDICATED: &str = "isolation.dedicated";

/// Feature name gating hybrid gateways: a gateway the org runs on its own
/// infrastructure and enrolls into the managed service itself, on an
/// enrollment token not bound to a published instance. Enterprise only.
pub const FEATURE_HYBRID_GATEWAYS: &str = "gateways.hybrid";

/// Feature name for high availability: the `cluster.*` coordinators that let
/// a gateway run more than one replica, self-hosted or managed. Enterprise
/// only; withheld through the `cluster.` paid namespace.
pub const FEATURE_CLUSTERING: &str = "clustering";

/// Feature name gating self-service enterprise SSO: an org owner connects
/// the org's own IdP and routes a verified email domain's sign-ins to it.
/// Team and Enterprise.
pub const FEATURE_SSO_ENTERPRISE: &str = "sso.enterprise";

/// Feature name gating interactive sign-in at the gateway's embedded
/// authorization server and the per-user store of enterprise IdP sign-ins
/// it keeps: a `governance.access.authorization_server.trusted_idps[].login`
/// block or an `authorization_server.interactive` block. Enterprise only.
pub const FEATURE_INTERACTIVE_LOGIN: &str = "sso.interactive_login";

/// Feature name gating DPoP-bound tokens (RFC 9449) at the gateway's
/// embedded authorization server: a
/// `governance.access.authorization_server.dpop` block with `enabled: true`.
/// A block with `enabled: false` (the default) turns nothing on and needs no
/// feature, whatever its other keys say. Enterprise only.
pub const FEATURE_DPOP: &str = "oauth.dpop";

/// Feature name gating rich authorization requests (RFC 9396) at the
/// gateway's embedded authorization server: a
/// `governance.access.authorization_server.authorization_details` block that
/// lists at least one type. A block whose `types` is empty (the default)
/// turns nothing on and needs no feature, whatever its `max_entries` says.
/// Enterprise only.
pub const FEATURE_RICH_AUTHORIZATION: &str = "oauth.rich_authorization";

/// Whether `plan` may reference plugins the customer publishes themselves,
/// rather than only first-party ones. Enterprise; asked through the feature
/// list so the licence stays the single source of what a plan grants.
pub fn allows_custom_plugins(plan: &str) -> bool {
    features_for(plan)
        .iter()
        .any(|f| f == FEATURE_CUSTOM_PLUGINS)
}

/// Verify a license JWT against one given Ed25519 public key.
///
/// Validates: signature, alg=`EdDSA`, audience contains
/// `expected_aud`, lic_ver ≤ `MAX_SUPPORTED_LIC_VER`, current
/// time within `nbf..exp`.
///
/// Returns the parsed claims on success. The key is whatever the caller
/// passes, so this is an issuer-side check (does a token carry what I signed);
/// deciding whether to honour a licence is [`verify_vendor_license`]'s job.
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

    #[error(
        "license is not signed by an MCPG licence issuer key this build trusts (kid `{0}`); \
         only licences MCPG issues are accepted"
    )]
    UntrustedIssuerKey(String),

    #[error("license is signed by issuer key `{0}`, which MCPG has revoked")]
    RevokedIssuerKey(String),

    #[error("license is signed by `{kid}`, a {role} issuer key, which is not accepted here")]
    IssuerRoleNotAccepted { kid: String, role: &'static str },

    #[error(
        "license is signed by staging issuer key `{0}` but does not mark non_production use; \
         a staging key signs only non-production licences"
    )]
    StagingKeyProductionLicense(String),

    #[error("the embedded licence issuer key set is malformed: {0}")]
    IssuerKeySet(String),

    #[error("the licence delivery proof does not verify: {0}")]
    DeliveryProof(String),
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
        // No tunnel-byte axis in the token: its plan's compiled allowance
        // stands, never "0 = unlimited".
        assert_eq!(c.quotas.tunnel_bytes_per_month, None);
        assert_eq!(
            c.quotas.tunnel_bytes_for("team"),
            plan_envelope("team").1.tunnel_bytes_per_month.unwrap()
        );
        // The same for included compute: the plan's hours, never unlimited.
        assert_eq!(c.quotas.included_compute_hours_per_month, None);
        assert_eq!(c.quotas.included_compute_hours_for("team"), 3 * MONTH_HOURS);
        assert_ne!(c.quotas.included_compute_hours_for("team"), 0);
    }

    #[test]
    fn included_compute_is_counted_in_s_equivalent_hours() {
        let hours = |plan: &str| {
            plan_envelope(plan)
                .1
                .included_compute_hours_per_month
                .unwrap()
        };
        assert_eq!(MONTH_HOURS, 31 * 24);
        assert_eq!(hours("team"), 3 * 31 * 24, "three always-on s gateways");
        assert_eq!(hours("pro"), 31 * 24, "one always-on s gateway");
        assert_eq!(hours("community"), 31 * 24);
        assert_eq!(hours("bogus"), hours("community"));
        assert_eq!(hours("enterprise"), 0, "0 = unlimited");
    }

    #[test]
    fn every_compute_type_has_an_s_equivalent_weight() {
        let weights: Vec<u64> = COMPUTE_SIZES
            .iter()
            .map(|s| s_equivalent_weight(s).expect("every compute type is weighted"))
            .collect();
        assert_eq!(weights, vec![1, 2, 4, 8]);
        for pair in weights.windows(2) {
            assert_eq!(pair[1], pair[0] * 2, "each type doubles the one before");
        }
        let order: Vec<&str> = COMPUTE_WEIGHTS.iter().map(|(s, _)| *s).collect();
        assert_eq!(order, COMPUTE_SIZES, "the weights follow COMPUTE_SIZES");
        assert_eq!(s_equivalent_weight("xxl"), None);
        assert_eq!(s_equivalent_weight(""), None);
    }

    #[test]
    fn the_included_compute_axis_falls_back_to_the_plan() {
        let old = Quotas::default();
        assert_eq!(old.included_compute_hours_for("pro"), MONTH_HOURS);
        assert_eq!(old.included_compute_hours_for("enterprise"), 0);
        let pinned = Quotas {
            included_compute_hours_per_month: Some(11),
            ..Quotas::default()
        };
        assert_eq!(pinned.included_compute_hours_for("team"), 11);
        let v = serde_json::to_value(Quotas::default()).unwrap();
        assert!(v.get("included_compute_hours_per_month").is_none(), "{v}");
        let v = serde_json::to_value(&pinned).unwrap();
        assert_eq!(v["included_compute_hours_per_month"], 11);
        assert_eq!(
            Quotas::default()
                .resolved_for("team")
                .included_compute_hours_per_month,
            Some(3 * MONTH_HOURS)
        );
        assert_eq!(
            pinned.resolved_for("team").included_compute_hours_per_month,
            Some(11)
        );
    }

    /// Every plan carries a tunnel-byte allowance, free is the smallest, and
    /// only enterprise is unlimited.
    #[test]
    fn tunnel_byte_allowance_scales_by_tier() {
        let bytes = |plan: &str| plan_envelope(plan).1.tunnel_bytes_per_month.unwrap();
        assert_eq!(bytes("community"), 5 * GIB);
        assert_eq!(bytes("pro"), 10 * GIB);
        assert_eq!(bytes("team"), 100 * GIB);
        assert!(bytes("community") < bytes("pro"));
        assert!(bytes("pro") < bytes("team"));
        assert_eq!(bytes("enterprise"), 0, "0 = unlimited");
        assert_eq!(bytes("bogus"), bytes("community"));
        // Carried value wins over the compiled one.
        let pinned = Quotas {
            tunnel_bytes_per_month: Some(7),
            ..Quotas::default()
        };
        assert_eq!(pinned.tunnel_bytes_for("team"), 7);
        // Serialized only when set, so a licence without it stays byte-identical.
        let v = serde_json::to_value(Quotas::default()).unwrap();
        assert!(v.get("tunnel_bytes_per_month").is_none(), "{v}");
    }

    /// A licence issued before the events axes reads the plan's compiled
    /// ones, and one that carries them keeps its own.
    #[test]
    fn the_events_axes_fall_back_to_the_plan() {
        let old = Quotas::default();
        assert_eq!(old.event_subscriptions_for("pro"), 100);
        assert_eq!(old.events_delivered_for("pro"), 1_000_000);
        assert_eq!(old.events_delivered_for("enterprise"), 0, "unlimited");
        let pinned = Quotas {
            event_subscriptions: Some(3),
            events_delivered_per_month: Some(9),
            ..Quotas::default()
        };
        assert_eq!(pinned.event_subscriptions_for("team"), 3);
        assert_eq!(pinned.events_delivered_for("team"), 9);
        let v = serde_json::to_value(Quotas::default()).unwrap();
        assert!(v.get("event_subscriptions").is_none(), "{v}");
        assert!(v.get("events_delivered_per_month").is_none(), "{v}");
    }

    #[test]
    fn the_event_plan_caps_fall_back_to_the_plan_and_tighten_on_free() {
        let old = Quotas::default();
        assert_eq!(old.events_ingested_for("community"), 10_000);
        assert_eq!(old.event_types_for("community"), 10);
        assert_eq!(old.event_retention_ms_for("community"), DAY_MS);
        assert_eq!(old.event_retention_events_for("community"), 1_000);
        assert_eq!(old.event_retention_bytes_for("community"), MIB);
        assert_eq!(old.event_retry_window_ms_for("community"), 5 * MINUTE_MS);
        assert_eq!(old.event_types_for("enterprise"), 0, "unlimited");
        for plan in ["pro", "team"] {
            assert!(old.event_types_for(plan) > old.event_types_for("community"));
            assert!(old.event_retention_bytes_for(plan) > MIB);
            assert!(old.event_retry_window_ms_for(plan) > 5 * MINUTE_MS);
        }
        let pinned = Quotas {
            event_types: Some(2),
            ..Quotas::default()
        };
        assert_eq!(pinned.event_types_for("team"), 2);
        let v = serde_json::to_value(Quotas::default()).unwrap();
        for key in [
            "events_ingested_per_month",
            "event_types",
            "event_retention_ms",
            "event_retention_events",
            "event_retention_bytes",
            "event_retry_window_ms",
        ] {
            assert!(v.get(key).is_none(), "{key}: {v}");
        }
    }

    #[test]
    fn resolved_quotas_name_what_is_enforced() {
        let resolved = Quotas::default().resolved_for("community");
        assert_eq!(resolved.event_subscriptions, Some(10));
        assert_eq!(resolved.events_ingested_per_month, Some(10_000));
        assert_eq!(resolved.event_retry_window_ms, Some(5 * MINUTE_MS));
        let pinned = Quotas {
            events_delivered_per_month: Some(0),
            ..Quotas::default()
        };
        assert_eq!(
            pinned.resolved_for("community").events_delivered_per_month,
            Some(0),
            "a pinned unlimited stays unlimited"
        );
    }

    use ed25519_dalek::SigningKey;
    use jsonwebtoken::{EncodingKey, Header};

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
                tunnel_bytes_per_month: None,
                included_compute_hours_per_month: None,
                event_subscriptions: None,
                events_delivered_per_month: None,
                events_ingested_per_month: None,
                event_types: None,
                event_retention_ms: None,
                event_retention_events: None,
                event_retention_bytes: None,
                event_retry_window_ms: None,
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
            non_production: false,
        }
    }

    #[test]
    fn the_term_follows_the_warning_and_grace_windows() {
        const DAY: i64 = 86_400;
        let exp = 1_900_000_000;
        assert_eq!(LicenseTerm::of(exp, exp - 31 * DAY), LicenseTerm::Current);
        assert_eq!(
            LicenseTerm::of(exp, exp - 30 * DAY),
            LicenseTerm::ExpiringSoon
        );
        assert_eq!(LicenseTerm::of(exp, exp - 1), LicenseTerm::ExpiringSoon);
        assert_eq!(LicenseTerm::of(exp, exp), LicenseTerm::Grace);
        assert_eq!(LicenseTerm::of(exp, exp + 14 * DAY - 1), LicenseTerm::Grace);
        assert_eq!(LicenseTerm::of(exp, exp + 14 * DAY), LicenseTerm::Lapsed);
        assert_eq!(grace_ends_at(exp), exp + 14 * DAY);
        // The unlicensed envelope never expires.
        assert_eq!(
            LicenseClaims::community(AUDIENCE_GATEWAY).term(Utc::now().timestamp()),
            LicenseTerm::Current
        );
    }

    /// A cloud licence keeps its plan seven days past `exp`, a self-host
    /// licence fourteen.
    #[test]
    fn the_grace_follows_the_issuer_role() {
        const DAY: i64 = 86_400;
        let exp = 1_900_000_000;
        let cloud = expiry_grace_days(IssuerRole::Cloud);
        assert_eq!(cloud, 7);
        assert_eq!(
            LicenseTerm::with_grace(exp, exp + 7 * DAY - 1, cloud),
            LicenseTerm::Grace
        );
        assert_eq!(
            LicenseTerm::with_grace(exp, exp + 7 * DAY, cloud),
            LicenseTerm::Lapsed
        );
        assert_eq!(grace_ends_after(exp, cloud), exp + 7 * DAY);
        assert_eq!(expiry_grace_days(IssuerRole::SelfHost), EXPIRY_GRACE_DAYS);
    }

    #[test]
    fn non_production_is_absent_unless_set_and_defaults_off() {
        let c = sample_claims(3600);
        let json = serde_json::to_value(&c).unwrap();
        assert!(json.get("non_production").is_none());
        let mut marked = c.clone();
        marked.non_production = true;
        let json = serde_json::to_value(&marked).unwrap();
        assert_eq!(json["non_production"], serde_json::json!(true));
        let back: LicenseClaims = serde_json::from_value(json).unwrap();
        assert!(back.non_production);
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

    /// Self-service enterprise SSO comes with Team and Enterprise, like SAML.
    #[test]
    fn enterprise_sso_is_granted_to_team_and_above() {
        for plan in ["team", "enterprise"] {
            assert!(
                features_for(plan)
                    .iter()
                    .any(|f| f == FEATURE_SSO_ENTERPRISE),
                "{plan} grants {FEATURE_SSO_ENTERPRISE}"
            );
        }
        for plan in ["community", "pro"] {
            assert!(
                !features_for(plan)
                    .iter()
                    .any(|f| f == FEATURE_SSO_ENTERPRISE),
                "{plan} does not grant {FEATURE_SSO_ENTERPRISE}"
            );
        }
        assert!(matches!(
            enforcement_of(FEATURE_SSO_ENTERPRISE),
            Some(FeatureEnforcement::DirectCheck(_))
        ));
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

    /// Interactive sign-in (and the stored IdP sign-ins behind it), DPoP-bound
    /// tokens and rich authorization requests are sold on the enterprise plan
    /// alone, and are checked where configs are admitted rather than at
    /// plugin load.
    #[test]
    fn authorization_server_features_are_enterprise_only() {
        assert_eq!(FEATURE_DPOP, "oauth.dpop");
        assert_eq!(FEATURE_RICH_AUTHORIZATION, "oauth.rich_authorization");
        for feature in [
            FEATURE_INTERACTIVE_LOGIN,
            FEATURE_DPOP,
            FEATURE_RICH_AUTHORIZATION,
        ] {
            for plan in ["community", "pro", "team", "bogus"] {
                assert!(
                    !features_for(plan).iter().any(|f| f == feature),
                    "{plan} must not grant {feature}"
                );
            }
            let enterprise = features_for("enterprise");
            assert_eq!(
                enterprise.iter().filter(|f| *f == feature).count(),
                1,
                "{feature}"
            );
            assert!(
                matches!(
                    enforcement_of(feature),
                    Some(FeatureEnforcement::DirectCheck(site)) if site.contains("license_gate")
                        && site.contains("publish_guard")
                ),
                "{feature}"
            );
            // A config surface, not a plugin: no plugin id maps to it.
            assert!(
                !["credential.oauth-id-jag", "identity.oidc", "identity.saml"]
                    .iter()
                    .any(|id| required_feature_for_plugin(id) == Some(feature)),
                "{feature}"
            );
        }
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
            "dev.mcpg.backend.oci-registry",
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

        let signing_key = SigningKey::generate(&mut rand::rng());
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
        assert!(plugin_load_violation(&team, "dev.mcpg.policy.cedar").is_none());
        // Kerberos needs `sso.kerberos`, an enterprise-only feature.
        assert!(plugin_load_violation(&team, "dev.mcpg.identity.kerberos").is_some());
    }

    /// High availability is Enterprise on every deployment: only the
    /// enterprise envelope admits the `cluster.*` coordinators, and only
    /// enterprise carries the `clustering` flag.
    #[test]
    fn clustering_is_enterprise_only() {
        let claims = |plan: &str| {
            let mut c = LicenseClaims::community("mcpg-gateway");
            let (entitlements, quotas) = plan_envelope(plan);
            c.plugin_entitlements = entitlements;
            c.quotas = quotas;
            c.features = features_for(plan);
            c.plan = plan.into();
            c
        };
        for coordinator in ["dev.mcpg.cluster.redis", "dev.mcpg.cluster.nats"] {
            for plan in ["community", "pro", "team"] {
                assert!(
                    matches!(
                        plugin_load_violation(&claims(plan), coordinator),
                        Some(LicenseError::PluginNotEntitled(_))
                    ),
                    "{plan} must not admit {coordinator}"
                );
            }
            assert!(
                plugin_load_violation(&claims("enterprise"), coordinator).is_none(),
                "enterprise admits {coordinator}"
            );
        }
        for plan in ["community", "pro", "team"] {
            assert!(
                !features_for(plan).iter().any(|f| f == FEATURE_CLUSTERING),
                "{plan} must not grant {FEATURE_CLUSTERING}"
            );
        }
        assert!(
            features_for("enterprise")
                .iter()
                .any(|f| f == FEATURE_CLUSTERING)
        );
        assert_eq!(
            enforcement_of(FEATURE_CLUSTERING),
            Some(FeatureEnforcement::PaidNamespace)
        );
    }

    /// A dedicated isolation tier and hybrid gateways on the managed service
    /// are Enterprise, each checked where the control plane admits it.
    #[test]
    fn dedicated_isolation_and_hybrid_gateways_are_enterprise_only() {
        for feature in [FEATURE_ISOLATION_DEDICATED, FEATURE_HYBRID_GATEWAYS] {
            for plan in ["community", "pro", "team"] {
                assert!(
                    !features_for(plan).iter().any(|f| f == feature),
                    "{plan} must not grant {feature}"
                );
            }
            assert!(features_for("enterprise").iter().any(|f| f == feature));
            assert!(matches!(
                enforcement_of(feature),
                Some(FeatureEnforcement::DirectCheck(_))
            ));
        }
    }

    /// The platform-coordination grant admits the one coordinator the platform
    /// adds, and no plan grants it.
    #[test]
    fn the_platform_coordination_grant_admits_only_the_platform_coordinator() {
        let mut pro = LicenseClaims::community("mcpg-cp");
        pro.features = features_for("pro");
        assert!(!admits_platform_coordinator(
            &pro,
            PLATFORM_COORDINATOR_PLUGIN
        ));
        pro.features.push(FEATURE_PLATFORM_COORDINATION.into());
        assert!(admits_platform_coordinator(
            &pro,
            PLATFORM_COORDINATOR_PLUGIN
        ));
        assert!(!admits_platform_coordinator(&pro, "dev.mcpg.cluster.redis"));
        for plan in ["community", "pro", "team", "enterprise"] {
            assert!(
                !features_for(plan).contains(&FEATURE_PLATFORM_COORDINATION.to_owned()),
                "{plan}"
            );
        }
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
