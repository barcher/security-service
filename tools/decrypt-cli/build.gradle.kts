// Phase 14 Stream M (SKS-M05) — operator decrypt CLI.
//
// Standalone Kotlin executable. NOT bundled into the running `security-app` docker
// image (CLAUDE.md "Shared Key Service" rule 24 — operator runs it on a workstation
// or jump-host). Distribution path: `./gradlew :tools:decrypt-cli:installDist` →
// `tools/decrypt-cli/build/install/decrypt-cli/` (a launcher shell script + libs).
//
// Per `feedback_operator_decrypt_cli_single_sided.md` this is the ONLY operator
// decrypt CLI in either repo — the monolith does NOT host a sibling. The CLI's
// scope is security-service-owned ciphertext only (proposal §3.2 list):
//   * `security_keys.deks.wrapped_dek_bytes`  → unwrap to bytes
//   * `security_keys.jwt_signing_keys.wrapped_private_key_bytes` (Stream K) → PEM
//   * future encrypted security-service state
//
// Module isolation: NOT under `adapters/` because it is a tools/operator module,
// not a hexagonal-arch adapter. Depends on `application`, `adapters/outbound/crypto`,
// `adapters/outbound/persistence` — all build-time only. NEVER imported by the
// running service.
plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.serialization)
    application
}

kotlin {
    jvmToolchain(21)
}

application {
    mainClass.set("com.shared.security.tools.decryptcli.DecryptCliMainKt")
    // SKS-H11 carryover — env loading uses reflection on Collections$UnmodifiableMap.
    applicationDefaultJvmArgs = listOf("--add-opens", "java.base/java.util=ALL-UNNAMED")
}

tasks.named<JavaExec>("run") {
    jvmArgs("--add-opens", "java.base/java.util=ALL-UNNAMED")
}

// Rename installDist output to a stable launcher name.
tasks.named<CreateStartScripts>("startScripts") {
    applicationName = "decrypt-cli"
}

dependencies {
    implementation(project(":domain"))
    implementation(project(":application"))
    implementation(project(":adapters:outbound:persistence"))
    implementation(project(":adapters:outbound:crypto"))
    implementation(project(":adapters:outbound:jwt-signing"))

    implementation(libs.kotlin.stdlib)
    implementation(libs.dotenv.kotlin)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.kotlinx.coroutines.core)
    implementation(libs.kotlinx.datetime)
    implementation(libs.exposed.core)
    implementation(libs.exposed.jdbc)
    implementation(libs.mysql.connector)
    implementation(libs.hikari)
    implementation(libs.koin.core)
    implementation(libs.logback.classic)

    testImplementation(libs.junit.jupiter)
    testImplementation(libs.mockk)
    testImplementation(libs.kotlinx.coroutines.test)
}

tasks.test {
    useJUnitPlatform()
}
