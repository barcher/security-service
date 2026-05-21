plugins {
    alias(libs.plugins.kotlin.jvm)
}

kotlin {
    jvmToolchain(21)
}

// Inbound scheduler adapter: Quartz jobs (KekRotationHealthJob, KekPriorTtlJob,
// DekRotationJob, AuditLogShipperJob, AuditRetentionJob, KekBackupVerifyJob).
// Quartz tables are created by the persistence adapter's Flyway migrations.

dependencies {
    implementation(project(":application"))
    implementation(project(":domain"))
    implementation(libs.kotlin.stdlib)
    implementation(libs.kotlinx.coroutines.core)
    implementation(libs.kotlinx.datetime)
    implementation(libs.koin.core)
    implementation(libs.quartz) {
        // c3p0 and mchange-commons-java are Quartz transitive dependencies. SecurityScheduler
        // uses RAMJobStore — no JDBC connection provider is needed; c3p0 is never used.
        exclude(group = "com.mchange", module = "c3p0")
        exclude(group = "com.mchange", module = "mchange-commons-java")
    }
    implementation(libs.logback.classic)

    testImplementation(libs.junit.jupiter)
    testImplementation(libs.mockk)
    testImplementation(libs.kotlinx.coroutines.test)
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.withType<Test> {
    useJUnitPlatform()
}
