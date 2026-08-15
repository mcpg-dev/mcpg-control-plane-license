# mcpg-control-plane-license

> The licensing vocabulary of MCPG: license-token claims, offline Ed25519 verification, plan envelopes, and the plugin entitlement gates.

An MCPG deployment's plan tier, plugin entitlements, quotas, feature flags and
residency boundary all travel in one Ed25519-signed JWT, and this crate is the
single definition of what that token says and how it is checked. Verification is
entirely offline — a gateway with a trusted public key can decide what it may
run with no network call to any licensing service — which is why the crate is
kept dependency-light and why the gateway links it unconditionally. It exposes
no issuing or signing API: minting license tokens belongs to the federation
issuer, and this crate only reads them.

## What's here
- `license::LicenseClaims` — every claim in a license token: the JWT frame
  (`iss`, `sub`, `aud`, `iat`, `exp`, `nbf`, `jti`, `lic_ver`), the tenant
  (`tenant_id`, `tenant_slug`, `plan`, `issued_to`), the grants
  (`plugin_entitlements`, `features`, `quotas`, `allowed_regions`,
  `residency_domain`, `support_tier`, `license_class`), and the deployment shape
  (`sovereign`, `airgap`, `grace`). Helpers: `is_currently_valid()`,
  `expires_at()`, `entitled_for_plugin()`, `allows_region()`, `has_feature()`,
  `support_tier()`, `tenant()`, `audiences()`.
- `license::verify_license(token, trust_anchor, expected_aud)` — checks the
  EdDSA signature, audience, `nbf`/`exp` with 60 seconds of leeway, and refuses
  a `lic_ver` above `MAX_SUPPORTED_LIC_VER`. Alongside it,
  `verifying_key_from_pem()` for SPKI PEM public keys and `verify_signature()`
  for non-JWT payloads.
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
  and the retention windows), where `0` means unlimited or "use the platform
  default".
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
