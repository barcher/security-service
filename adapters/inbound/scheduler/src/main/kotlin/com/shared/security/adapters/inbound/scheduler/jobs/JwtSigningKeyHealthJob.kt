package com.shared.security.adapters.inbound.scheduler.jobs

import com.shared.security.application.usecases.jwt.RunJwtSigningKeyHealthCheckUseCase
import kotlinx.coroutines.runBlocking
import org.quartz.DisallowConcurrentExecution
import org.quartz.Job
import org.quartz.JobExecutionContext
import org.slf4j.LoggerFactory

/**
 * Hourly probe: signs + verifies a fixed payload against the ACTIVE JWT signing key. Emits
 * `JWKS_HEALTH_CHECK_FAILED` on any failure path; success is silent (same convention as
 * `KekRotationHealthJob`).
 */
@DisallowConcurrentExecution
class JwtSigningKeyHealthJob(private val useCase: RunJwtSigningKeyHealthCheckUseCase) : Job {
    private val logger = LoggerFactory.getLogger(JwtSigningKeyHealthJob::class.java)

    override fun execute(context: JobExecutionContext) {
        logger.debug("Firing JwtSigningKeyHealthJob")
        when (val result = runBlocking { useCase.execute() }) {
            RunJwtSigningKeyHealthCheckUseCase.Result.Ok -> Unit
            RunJwtSigningKeyHealthCheckUseCase.Result.NoActiveKey ->
                logger.warn("JwtSigningKeyHealthJob: no ACTIVE signing key configured")
            is RunJwtSigningKeyHealthCheckUseCase.Result.Failed ->
                logger.error("JwtSigningKeyHealthJob: probe failed reason={}", result.reason)
        }
    }
}
