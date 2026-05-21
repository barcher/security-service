buildscript {
    repositories {
        mavenCentral()
    }
    dependencies {
        classpath("org.flywaydb:flyway-mysql:11.20.3")
        classpath("com.mysql:mysql-connector-j:9.1.0")
    }
}

plugins {
    alias(libs.plugins.kotlin.jvm) apply false
    alias(libs.plugins.kotlin.serialization) apply false
    alias(libs.plugins.ktor) apply false
    alias(libs.plugins.ktlint) apply false
    alias(libs.plugins.detekt) apply false
    alias(libs.plugins.flyway) apply false
}

allprojects {
    group = "com.shared.security"
    version = "1.0.0"
}

// SKS-H11: `.env` loading was previously done here at the Gradle layer as a temporary
// workaround. The application now loads `.env` directly at the top of `Application.main()`
// via `io.github.cdimascio:dotenv-kotlin`, so the same env vars are visible regardless of
// launch path (gradle run, java -jar, IDE, prod container). No Gradle-side .env coupling.

subprojects {
    apply(plugin = "org.jlleitschuh.gradle.ktlint")
    apply(plugin = "io.gitlab.arturbosch.detekt")

    extensions.configure<org.jlleitschuh.gradle.ktlint.KtlintExtension> {
        android.set(false)
        outputToConsole.set(true)
        enableExperimentalRules.set(false)
    }

    extensions.configure<io.gitlab.arturbosch.detekt.extensions.DetektExtension> {
        config.setFrom("${rootProject.projectDir}/detekt.yml")
        buildUponDefaultConfig = true
    }
}
