plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.serialization)
}

kotlin {
    jvmToolchain(21)
}

// Inbound HTTP adapter for the OAuth 2.0 / OIDC provider surface.
//
// O.0 serves only OIDC discovery (`GET /.well-known/openid-configuration`). The `/token`,
// `/authorize`, and `/userinfo` handlers arrive in later phases.
//
// Dependency rule (oauth proposal §6.2, guards S-23 / S-29 — proposed S-27/S-29):
// this module depends ONLY on `:application` and `:contracts:oauth-oidc`. It MUST NOT depend
// on any `adapters:outbound:*` module (persistence/crypto/jwt-signing) — cross-cutting access
// flows through application-layer ports. ArchUnit enforces this in `OAuthModuleDependencyDirectionTest`.

dependencies {
    implementation(project(":application"))
    implementation(project(":domain"))
    implementation(project(":contracts:oauth-oidc"))
    implementation(libs.kotlin.stdlib)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.ktor.server.core)
    implementation(libs.ktor.serialization.kotlinx.json)
    implementation(libs.logback.classic)

    testImplementation(libs.junit.jupiter)
    testImplementation(libs.mockk)
    testImplementation(libs.ktor.server.test.host)
    testImplementation(libs.ktor.server.content.negotiation)
    testImplementation(libs.ktor.client.content.negotiation)
    testImplementation(libs.kotlinx.coroutines.test)
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.withType<Test> {
    useJUnitPlatform()
}
