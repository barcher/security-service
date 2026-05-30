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
    implementation(project(":contracts:oauth-oidc"))
    implementation(project(":adapters:inbound:http"))
    implementation(project(":adapters:inbound:http-oauth"))
    implementation(project(":adapters:inbound:scheduler"))
    implementation(project(":adapters:outbound:persistence"))
    implementation(libs.exposed.core)
    implementation(libs.exposed.jdbc)
    implementation(project(":adapters:outbound:crypto"))
    implementation(project(":adapters:outbound:jwt-signing"))

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
    testImplementation(libs.testcontainers.mysql)
    testImplementation(libs.testcontainers.junit)
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.kotlinx.datetime)
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

// Unit tests: exclude @Tag("integration") so `./gradlew test` runs without Docker.
tasks.named<Test>("test") {
    useJUnitPlatform {
        excludeTags("integration")
    }
}

// Integration tests: only @Tag("integration") tests — requires Docker with MySQL 8.0
tasks.register<Test>("integrationTest") {
    useJUnitPlatform {
        includeTags("integration")
    }
    group = "verification"
    description = "Runs integration tests (requires Docker)"
    testClassesDirs = sourceSets["test"].output.classesDirs
    classpath = sourceSets["test"].runtimeClasspath
    shouldRunAfter("test")
}

// Run the application from the security-service root so relative paths in .env
// (./secrets/keystore.p12, ./secrets/truststore.p12, KEK_MOUNT_DIR=./secrets, etc.)
// resolve against the same directory the operator launches from. By default
// Gradle's run task sets CWD to the module's projectDir (which would be
// security-service/infrastructure/), breaking every ./secrets/... path.
tasks.named<JavaExec>("run") {
    workingDir = rootProject.projectDir
}

// `runFresh` — touch every Kotlin source so its mtime is "now", then clean every
// module's build outputs + run. The touch is important: some editors (including
// agentic-tool atomic-rewrite paths) preserve a file's original mtime when they
// rewrite content, which makes Gradle's incremental compiler think the source is
// older than the last compiled .class and skip recompilation. Result: "I rebuilt and
// it still doesn't work" symptoms even after a `clean`. Touching the sources first
// guarantees they look newer than any cached output.
tasks.register("touchKotlinSources") {
    group = "build"
    description = "Bump mtime on every .kt under src/ so Gradle definitely re-runs the compiler."
    doLast {
        rootProject.allprojects.forEach { p ->
            val srcDir = p.projectDir.resolve("src")
            if (srcDir.isDirectory) {
                p.fileTree(srcDir) { include("**/*.kt") }.forEach { it.setLastModified(System.currentTimeMillis()) }
            }
        }
    }
}

tasks.register("runFresh") {
    group = "application"
    description = "Touch sources, clean all modules, then run the security-service. Use when stale build cache is suspected."
    dependsOn("touchKotlinSources")
    dependsOn(
        rootProject.allprojects
            .mapNotNull { it.tasks.findByName("clean") },
    )
    finalizedBy(tasks.named("run"))
}
