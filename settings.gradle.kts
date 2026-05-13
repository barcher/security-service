rootProject.name = "security-service"

include(
    "domain",
    "application",
    "adapters:inbound:http",
    "adapters:inbound:scheduler",
    "adapters:outbound:persistence",
    "adapters:outbound:crypto",
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
