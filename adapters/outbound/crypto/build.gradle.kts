plugins {
    alias(libs.plugins.kotlin.jvm)
}

kotlin {
    jvmToolchain(21)
}

// This module houses only ML-KEM-768 post-quantum KEM operations + HKDF-SHA-512 wrap.
// It must not depend on :domain or any other adapter module. Only :application is allowed
// (for the CryptoKeyServicePort contract). ArchUnit rules S-1..S-3 enforce this in tests.

dependencies {
    implementation(project(":application"))
    implementation(libs.bcprov.jdk18on)
    implementation(libs.kotlin.stdlib)
    implementation(libs.kotlinx.coroutines.core)

    testImplementation(libs.junit.jupiter)
    testImplementation(libs.archunit.junit5)
    testImplementation(libs.kotlinx.coroutines.test)
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.withType<Test> {
    useJUnitPlatform()
}
