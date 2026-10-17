# mcpg-control-plane-license

> The licensing vocabulary of MCPG: license-token claims, offline Ed25519 verification, plan envelopes, and the plugin entitlement gates.

An MCPG deployment's plan tier, plugin entitlements, quotas, feature flags and
residency boundary all travel in one Ed25519-signed JWT, and this crate is the
single definition of what that token says and how it is checked. Verification is
entirely offline — against MCPG's licence issuer public keys, which this crate
compiles in — so a gateway decides what it may run with no network call to any
licensing service, which is why the crate is kept dependency-light and why the
gateway links it unconditionally. It exposes no licence issuing API outside
test builds: minting license tokens belongs to MCPG's issuers, and this crate
only reads them. The one thing it signs is a delivery proof, with a key the
caller holds (`delivery::encode_delivery_proof`).

## What's here
- `license::LicenseClaims` — every claim in a license token: the JWT frame
  (`iss`, `sub`, `aud`, `iat`, `exp`, `nbf`, `jti`, `lic_ver`), the tenant
  (`tenant_id`, `tenant_slug`, `plan`, `issued_to`), the grants
  (`plugin_entitlements`, `features`, `quotas`, `allowed_regions`,
  `residency_domain`, `support_tier`, `license_class`), and the deployment shape
  (`sovereign`, `airgap`, `grace`). Helpers: `is_currently_valid()`,
  `expires_at()`, `entitled_for_plugin()`, `allows_region()`, `has_feature()`,
  `support_tier()`, `tenant()`, `audiences()`.
- `trust` — the embedded, append-only set of MCPG licence issuer keys
  (`src/issuer_keys.txt`), each with its `kid` (RFC 7638 thumbprint), issuer
  role (`self_host` | `cloud` | `platform`, which signs no licence, only
  delivery proofs) and environment (`production` | `staging`).
  `license::verify_vendor_license(token, policy)` is how a deployment decides
  whether to honour a licence: the key named by the header `kid` must be
  embedded, unrevoked and of a role the caller accepts; the token must carry
  `typ: mcpg-license+jwt`, the caller's audience, a valid signature, `nbf` and
  (unless the caller applies its own grace policy) `exp`; and a staging key
  admits only a licence marked `non_production`. `LicenseTerm` classifies a
  licence against the 30-day expiry warning and its grace period:
  `expiry_grace_days` gives a self-host licence 14 days and an mcpg.cloud
  licence 7 (its refresh is failing; a revoked one is replaced at once). In
  builds with debug assertions (tests), `trust::test_override` trusts keys a
  test generates; release builds (`opt`) do not contain it, which
  `:release_trust_check` proves. MCPG's licence key ceremony fills the set:
  `mcpg-license keygen --role <role> --environment <environment>` prints the
  record each new key appends.
- `delivery` — the proof an mcpg.cloud control plane sends with each licence
  it delivers down a gateway's Channel: a JWT (`typ: mcpg-delivery+jwt`,
  `aud: mcpg-gateway-delivery`) signed with a `platform` key over the org, the
  licence's digest, the Channel's nonce and the instance uid the Channel is
  authenticated as. `verify_delivery_proof` checks a live one;
  `verify_cached_delivery_proof` checks the one a gateway kept with its cached
  delivery, which holds for `LAST_KNOWN_GOOD_SECS` (24 hours) after it was
  signed.
- `license::verify_license(token, key, expected_aud)` — checks a token
  against one given key: the EdDSA signature, audience, `nbf`/`exp` with 60
  seconds of leeway, and a `lic_ver` above `MAX_SUPPORTED_LIC_VER`. An
  issuer-side check; deciding whether to honour a licence is
  `verify_vendor_license`'s job. Alongside it, `verifying_key_from_pem()` for
  SPKI PEM public keys and `verify_signature()` for non-JWT payloads.
- `license::LicenseClaims::community(aud)` — the synthetic unlicensed envelope.
  It is never signed and never serialized as a token; it exists so a deployment
  with no license evaluates exactly the same entitlement checks as a licensed
  one instead of taking a separate code path.
- `license::plan_envelope(plan)`, `features_for(plan)`, `regions_for(plan)`,
  `is_free_plan(plan)` — the single source of truth for what a plan tier grants,
  shared by every issuer so a plan means the same thing regardless of who minted
  the token. An unrecognised plan falls back to the community envelope, so the
  failure mode is under-entitlement rather than a refusal.
- The entitlement gates: `required_feature_for_plugin(plugin_id)` for premium
  plugins that live inside a namespace a lower tier can already bind,
  `PAID_NAMESPACES` and `is_entitlement_gated(plugin_id)` for namespaces with no
  free members, and `plugin_load_violation(claims, plugin_id)`, which returns
  `None` for anything permitted. Free and third-party plugin ids always pass.
  Matching accepts both the canonical reverse-DNS id and the short namespaced
  form, since `FIRST_PARTY_ID_PREFIX` is stripped before the glob runs.
- `license::Quotas` — the enforceable ceilings (`gateways`, `plugins`,
  `rps_per_gateway`, `workspaces`, `users`, `tool_calls_per_month`, `tunnels`,
  `tunnel_bytes_per_month`, `included_compute_hours_per_month` (managed-instance
  hours a month includes, counted in s-equivalents), and the retention
  windows), where `0` means
  unlimited or "use the platform default", and the MCP Events axes, where `0`
  means unlimited: `event_subscriptions` (live readers per gateway: webhook
  subscriptions, poll leases, open streams and the upstream subscriptions
  held for imported types), `events_delivered_per_month`,
  `events_ingested_per_month`, `event_types` (declared and imported types one
  gateway serves), `event_retention_ms`, `event_retention_events` and
  `event_retention_bytes` (what one event log keeps) and
  `event_retry_window_ms` (the longest webhook retry window).
  `tunnel_bytes_per_month`, `included_compute_hours_per_month` and the event
  axes are absent from a token issued before they existed; an absent axis
  reads the plan's compiled value, never unlimited. Read each through its
  `Quotas::*_for(plan)` accessor (`tunnel_bytes_for`,
  `included_compute_hours_for`, `event_subscriptions_for`, `events_delivered_for`,
  `events_ingested_for`, `event_types_for`, `event_retention_ms_for`,
  `event_retention_events_for`, `event_retention_bytes_for`,
  `event_retry_window_ms_for`), which falls back to the plan's compiled
  value. `Quotas::resolved_for(plan)` returns every such axis resolved, and
  `clear_event_caps` / `copy_event_caps` set the event axes as a group.
  `COMPUTE_SIZES` lists every compute type, smallest first, and
  `COMPUTE_WEIGHTS` / `s_equivalent_weight(size)` give the s-equivalent hours
  one instance-hour of each type counts for (`s` 1, `m` 2, `l` 4, `xl` 8).
- `license::LicenseError` — `Verification`, `UnsupportedVersion`,
  `PluginNotEntitled` and `FeatureNotLicensed { plugin, feature }`.
- Vocabulary constants: `SUPPORT_TIERS` and `SUPPORT_TIER_NONE`,
  `LICENSE_CLASSES` and `LICENSE_CLASS_SUBSCRIPTION`, the `FEATURE_SUPPORT_*`
  flags, with `is_known_support_tier()`, `is_known_license_class()` and
  `support_features_for(tier)`.
- `ids` — the typed identifiers the claims are expressed in: `OrgId`,
  `WorkspaceId`, `EnvironmentId`, `InstanceId`, `UserId`, `SessionId`, the
  validated `OrgSlug` / `WorkspaceSlug` / `InstanceSlug` / `CustomHostname`
  newtypes with their `SlugError` and `HostnameError`, `RESERVED_SLUGS` and
  `is_reserved()`, and `tenant_claim_slug()` for deriving a tenant slug from an
  identity-provider claim.

## Used by
- `apps/gateway`, which links it unconditionally so a standalone deployment can
  enforce the plugin load gate offline.
- `libs/control-plane/core`, which re-exports `ids` and `license` so the control
  plane, the federation issuer and the CLIs reach them through one dependency.

## Build / test
```bash
cargo build -p mcpg-control-plane-license
cargo test  -p mcpg-control-plane-license
```

## Licence
Apache-2.0. That is the licence of this crate's own source; the tokens it
verifies are a separate, commercial matter.

## See also
- [Cloud overview](https://mcpg.dev/docs/cloud/overview) — where license tokens come from.
- [Plugin catalogue](https://mcpg.dev/docs/plugins/plugin-catalogue) — the plugin ids the entitlement globs address.
- `libs/control-plane/core` — the crate that re-exports this one.
