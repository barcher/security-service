plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.serialization)
}

kotlin {
    jvmToolchain(21)
}

// Contracts module: pure OAuth 2.0 / OIDC wire DTOs + error codes. Zero adapter
// dependencies (no Ktor, no Exposed, no crypto). This is the shared contract surface the
// `http-oauth` inbound module serializes to/from, and which a future consumer-side OAuth
// client in shared-security-client can depend on without pulling any server internals —
// mirroring the existing `client/crypto` ⟂ `client/jwt` isolation.
//
// Dependency rule: this module depends on NOTHING in this repo. It is the leaf of the
// OAuth dependency graph (oauth proposal §6.2). It may depend only on kotlinx-serialization
// for the @Serializable wire shapes.

dependencies {
    implementation(libs.kotlin.stdlib)
    implementation(libs.kotlinx.serialization.json)

    testImplementation(libs.junit.jupiter)
    testImplementation(libs.kotlinx.serialization.json)
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.withType<Test> {
    useJUnitPlatform()
}
