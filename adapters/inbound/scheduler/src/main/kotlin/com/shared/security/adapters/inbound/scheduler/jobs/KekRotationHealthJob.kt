package com.shared.security.adapters.inbound.scheduler.jobs

import com.shared.security.application.usecases.RunKekHealthCheckUseCase
import kotlinx.coroutines.runBlocking
import org.quartz.DisallowConcurrentExecution
import org.quartz.Job
import org.quartz.JobExecutionContext
import org.slf4j.LoggerFactory

/**
 * Hourly probe: generates + unwraps a DEK to verify the active KEK is functional.
 * Emits `HEALTH_CHECK_OK` or `HEALTH_CHECK_FAILED` to the audit chain.
 *
 * @DisallowConcurrentExecution prevents two health probes running simultaneously across a
 * fast-clock or misconfigured trigger; a single probe per tick is sufficient.
 */
@DisallowConcurrentExecution
class KekRotationHealthJob(private val useCase: RunKekHealthCheckUseCase) : Job {
    private val logger = LoggerFactory.getLogger(KekRotationHealthJob::class.java)

    override fun execute(context: JobExecutionContext) {
        logger.debug("Firing KekRotationHealthJob")
        runBlocking { useCase.execute() }
    }
}
