rootProject.name = "security-service"

include(
    "domain",
    "application",
    // OAuth/OIDC wire contracts: pure DTOs + error codes, zero adapter deps. Leaf of the
    // OAuth dependency graph; a future consumer-side OAuth client can depend on it without
    // pulling any server internals (mirrors the shared-client crypto ⟂ jwt split).
    "contracts:oauth-oidc",
    "adapters:inbound:http",
    // OAuth/OIDC inbound HTTP surface (OIDC discovery now; /token + /authorize land later).
    // Depends only on :application + :contracts:oauth-oidc — never an outbound adapter.
    "adapters:inbound:http-oauth",
    "adapters:inbound:scheduler",
    "adapters:outbound:persistence",
    "adapters:outbound:crypto",
    // Stream K v0.2 (SKS-K04b): JWT signing primitives live in their own submodule,
    // never collocated with the KEK/DEK crypto module per the adapter-module isolation
    // rule.
    "adapters:outbound:jwt-signing",
    "infrastructure",
    // Stream M (SKS-M05): standalone operator decrypt CLI. NOT under adapters/ —
    // this is an operator tools module, never imported by the running service. Per
    // feedback_operator_decrypt_cli_single_sided.md this is the only operator decrypt
    // CLI in either repo; the monolith does not host a sibling.
    "tools:decrypt-cli",
)

pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
    }
}

dependencyResolutionManagement {
    repositories {
        mavenCentral()
    }
}
