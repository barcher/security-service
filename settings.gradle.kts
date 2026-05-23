rootProject.name = "security-service"

include(
    "domain",
    "application",
    "adapters:inbound:http",
    "adapters:inbound:scheduler",
    "adapters:outbound:persistence",
    "adapters:outbound:crypto",
    // Stream K v0.2 (SKS-K04b): JWT signing primitives live in their own submodule,
    // never collocated with the KEK/DEK crypto module per the adapter-module isolation
    // rule.
    "adapters:outbound:jwt-signing",
    "infrastructure",
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
