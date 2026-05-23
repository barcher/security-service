package com.shared.security.adapters.inbound.scheduler.jobs

import com.shared.security.application.usecases.jwt.RunJwtSigningKeyRetentionUseCase
import kotlinx.coroutines.runBlocking
import org.quartz.DisallowConcurrentExecution
import org.quartz.Job
import org.quartz.JobExecutionContext
import org.slf4j.LoggerFactory

/**
 * Daily sweep: QUIESCED → RETIRED (after retentionWindow) and RETIRED → DELETED
 * (after retain_until). Mirrors `AuditRetentionJob` in shape; differs in that JWT key
 * retention has a stricter floor enforced by [com.shared.security.application.ports.JwtSigningKeyRepository.retireQuiesced].
 */
@DisallowConcurrentExecution
class JwtSigningKeyRetentionJob(private val useCase: RunJwtSigningKeyRetentionUseCase) : Job {
    private val logger = LoggerFactory.getLogger(JwtSigningKeyRetentionJob::class.java)

    override fun execute(context: JobExecutionContext) {
        val summary = runBlocking { useCase.execute() }
        logger.info(
            "JwtSigningKeyRetentionJob: retired={} deleted={}",
            summary.retired,
            summary.deleted,
        )
    }
}
