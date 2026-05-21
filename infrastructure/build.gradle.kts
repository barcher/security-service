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
    // SKS-H11: the .env loader uses reflection on java.util.Collections$UnmodifiableMap
    // to inject entries into the process env. JDK 9+ blocks `setAccessible(true)` on
    // `java.base/java.util` types unless the module is explicitly opened. Bake the flag
    // into the distributed startup scripts AND the run task (Gradle's `application`
    // plugin doesn't reliably propagate applicationDefaultJvmArgs to the `run` task
    // across all Gradle versions, so we also set it directly on the task below).
    applicationDefaultJvmArgs = listOf("--add-opens", "java.base/java.util=ALL-UNNAMED")
}

// Belt-and-suspenders for `./gradlew :infrastructure:run` — see comment in `application {}`.
tasks.named<JavaExec>("run") {
    jvmArgs("--add-opens", "java.base/java.util=ALL-UNNAMED")
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
    implementation(libs.dotenv.kotlin)
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

// Run the application from the security-service root so relative paths in .env
// (./secrets/keystore.p12, ./secrets/truststore.p12, KEK_MOUNT_DIR=./secrets, etc.)
// resolve against the same directory the operator launches from. By default
// Gradle's run task sets CWD to the module's projectDir (which would be
// security-service/infrastructure/), breaking every ./secrets/... path.
tasks.named<JavaExec>("run") {
    workingDir = rootProject.projectDir
}
