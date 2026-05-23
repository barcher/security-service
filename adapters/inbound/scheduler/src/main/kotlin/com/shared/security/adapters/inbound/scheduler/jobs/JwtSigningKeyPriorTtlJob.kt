package com.shared.security.adapters.inbound.scheduler.jobs

import com.shared.security.application.usecases.jwt.RunJwtSigningKeyPriorTtlUseCase
import kotlinx.coroutines.runBlocking
import org.quartz.DisallowConcurrentExecution
import org.quartz.Job
import org.quartz.JobExecutionContext
import org.slf4j.LoggerFactory

/**
 * Daily sweep: PRIOR JWT signing keys whose `activated_at + ttl < now` are quiesced.
 * Quiesced keys disappear from /v1/jwks and stop being used by consumers' JWKS caches.
 */
@DisallowConcurrentExecution
class JwtSigningKeyPriorTtlJob(private val useCase: RunJwtSigningKeyPriorTtlUseCase) : Job {
    private val logger = LoggerFactory.getLogger(JwtSigningKeyPriorTtlJob::class.java)

    override fun execute(context: JobExecutionContext) {
        val summary = runBlocking { useCase.execute() }
        logger.info(
            "JwtSigningKeyPriorTtlJob: candidates={} quiesced={} blockedByTtl={}",
            summary.candidatesEvaluated,
            summary.quiesced,
            summary.blockedByTtl,
        )
    }
}
