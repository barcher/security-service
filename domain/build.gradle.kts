plugins {
    alias(libs.plugins.kotlin.jvm)
}

kotlin {
    jvmToolchain(21)
}

// Domain module: pure Kotlin domain types for the security service.
// No framework dependencies. No I/O. No coroutines.

dependencies {
    implementation(libs.kotlin.stdlib)
    implementation(libs.kotlinx.datetime)

    testImplementation(libs.junit.jupiter)
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.withType<Test> {
    useJUnitPlatform()
}
