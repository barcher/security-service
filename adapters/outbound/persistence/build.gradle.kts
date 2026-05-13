plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.flyway)
}

kotlin {
    jvmToolchain(21)
}

// Outbound persistence adapter: Exposed-based repositories for the security service's
// own MySQL (security-mysql, host port 3308 in dev). Flyway location:
// classpath:security-db/migration.

dependencies {
    implementation(project(":application"))
    implementation(project(":domain"))
    implementation(libs.kotlin.stdlib)
    implementation(libs.kotlinx.datetime)
    implementation(libs.kotlinx.coroutines.core)
    implementation(libs.exposed.core)
    implementation(libs.exposed.jdbc)
    implementation(libs.exposed.kotlin.datetime)
    implementation(libs.exposed.json)
    implementation(libs.hikari)
    implementation(libs.mysql.connector)
    implementation(libs.flyway.core)
    implementation(libs.flyway.mysql)
    implementation(libs.koin.core)
    implementation(libs.logback.classic)

    testImplementation(libs.junit.jupiter)
    testImplementation(libs.mockk)
    testImplementation(libs.testcontainers.mysql)
    testImplementation(libs.testcontainers.junit)
    testImplementation(libs.kotlinx.coroutines.test)
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.withType<Test> {
    useJUnitPlatform()
}
