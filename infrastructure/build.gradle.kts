plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.ktor)
    application
}

kotlin {
    jvmToolchain(21)
}

application {
    mainClass.set("com.shared.security.infrastructure.ApplicationKt")
}

ktor {
    fatJar {
        archiveFileName.set("security-service.jar")
    }
}

// Infrastructure: composition root. Wires DI, starts the Ktor server, loads config.
// May depend on every module; nothing depends on infrastructure.

dependencies {
    implementation(project(":domain"))
    implementation(project(":application"))
    implementation(project(":adapters:inbound:http"))
    implementation(project(":adapters:inbound:scheduler"))
    implementation(project(":adapters:outbound:persistence"))
    implementation(libs.exposed.core)
    implementation(libs.exposed.jdbc)
    implementation(project(":adapters:outbound:crypto"))

    implementation(libs.kotlin.stdlib)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.kotlinx.coroutines.core)
    implementation(libs.kotlinx.datetime)

    implementation(libs.ktor.server.core)
    implementation(libs.ktor.server.netty)
    implementation(libs.ktor.server.content.negotiation)
    implementation(libs.ktor.server.status.pages)
    implementation(libs.ktor.server.call.logging)
    implementation(libs.ktor.server.metrics.micrometer)
    implementation(libs.ktor.server.rate.limit)
    implementation(libs.ktor.serialization.kotlinx.json)
    implementation(libs.koin.core)
    implementation(libs.koin.ktor)
    implementation(libs.micrometer.registry.prometheus)
    implementation(libs.logback.classic)

    testImplementation(libs.junit.jupiter)
    testImplementation(libs.mockk)
    testImplementation(libs.ktor.server.test.host)
    testImplementation(libs.archunit.junit5)
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.withType<Test> {
    useJUnitPlatform()
}
