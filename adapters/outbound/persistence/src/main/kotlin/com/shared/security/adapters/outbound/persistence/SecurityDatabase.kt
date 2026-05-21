package com.shared.security.adapters.outbound.persistence

import com.zaxxer.hikari.HikariConfig
import com.zaxxer.hikari.HikariDataSource
import org.flywaydb.core.Flyway
import org.jetbrains.exposed.sql.Database
import org.slf4j.LoggerFactory
import javax.sql.DataSource

/**
 * Owns the JDBC DataSource and the Exposed `Database` handle for the security service.
 *
 * One [SecurityDatabase] instance per process; constructed once at startup, passed
 * through DI to every repository. Closes the pool on [close].
 *
 * **Migrations are the responsibility of [SecurityFlywayMigrator]** — `SecurityDatabase`
 * does not auto-migrate. The composition root runs migrations on startup *before* binding
 * any repository, so a misordered schema surfaces as a Flyway error not an Exposed error
 * deep in a route handler.
 */
class SecurityDatabase private constructor(
    private val pool: HikariDataSource,
    val database: Database,
) : AutoCloseable {
    /** Exposed only as the more general type so downstream modules don't need a Hikari dep. */
    val dataSource: DataSource get() = pool

    override fun close() {
        pool.close()
    }

    companion object {
        private const val POOL_NAME = "security-hikari"
        private const val DRIVER = "com.mysql.cj.jdbc.Driver"
        private val logger = LoggerFactory.getLogger(SecurityDatabase::class.java)

        fun create(config: SecurityDatabaseConfig): SecurityDatabase {
            logger.info(
                "Creating {} pool: url={} user={} size={}",
                POOL_NAME,
                config.jdbcUrl,
                config.user,
                config.poolSize,
            )
            val hikari =
                HikariDataSource(
                    HikariConfig().apply {
                        poolName = POOL_NAME
                        jdbcUrl = config.jdbcUrl
                        username = config.user
                        password = config.password
                        maximumPoolSize = config.poolSize
                        minimumIdle = 2
                        driverClassName = DRIVER
                        connectionTimeout = 30_000
                        idleTimeout = 300_000
                        maxLifetime = 900_000
                        keepaliveTime = 60_000
                        isAutoCommit = false
                        transactionIsolation = "TRANSACTION_REPEATABLE_READ"
                    },
                )
            val db = Database.connect(hikari)
            return SecurityDatabase(pool = hikari, database = db)
        }
    }
}

/**
 * Runs Flyway migrations against the security service's MySQL using
 * `classpath:security-db/migration` as the location. Idempotent — safe to call on every
 * startup; only un-applied migrations execute.
 */
class SecurityFlywayMigrator(private val dataSource: DataSource) {
    private val logger = LoggerFactory.getLogger(SecurityFlywayMigrator::class.java)

    fun migrate() {
        logger.info("Running security-service Flyway migrations from classpath:security-db/migration")
        val flyway =
            Flyway.configure()
                .dataSource(dataSource)
                .locations("classpath:security-db/migration")
                .load()
        val result = flyway.migrate()
        logger.info(
            "Flyway migrate completed: migrationsExecuted={} success={}",
            result.migrationsExecuted,
            result.success,
        )
    }
}
