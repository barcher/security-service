plugins {
    alias(libs.plugins.kotlin.jvm)
}

kotlin {
    jvmToolchain(21)
}

// SKS-K04b — JWT signing primitives submodule. Houses Es256SigningService and any
// future JWT-specific crypto primitive. **Strictly isolated** from
// adapters/outbound/crypto/ (the KEK/DEK module). Does NOT depend on
// :adapters:outbound:crypto; does NOT import MlKemService or CryptoKeyServicePort.
// The two crypto submodules are sibling concerns that talk only through
// KekEnvelopePort (defined in :application, implemented by KekEnvelopeAdapter in
// adapters/outbound/crypto/, consumed by jwt/ use cases in :application). Enforced by
// ArchUnit rule S-13 in :infrastructure tests.

dependencies {
    implementation(project(":application"))
    implementation(libs.bcprov.jdk18on)
    implementation(libs.kotlin.stdlib)
    implementation(libs.kotlinx.coroutines.core)
    implementation(libs.logback.classic)

    testImplementation(libs.junit.jupiter)
    testImplementation(libs.archunit.junit5)
    testImplementation(libs.kotlinx.coroutines.test)
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.withType<Test> {
    useJUnitPlatform()
}
