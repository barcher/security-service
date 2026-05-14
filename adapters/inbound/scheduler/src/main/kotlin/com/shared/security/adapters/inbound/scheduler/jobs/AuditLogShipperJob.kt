package com.shared.security.adapters.inbound.scheduler.jobs

import com.shared.security.application.usecases.RunAuditLogShipperUseCase
import kotlinx.coroutines.runBlocking
import org.quartz.DisallowConcurrentExecution
import org.quartz.Job
import org.quartz.JobExecutionContext
import org.slf4j.LoggerFactory

@DisallowConcurrentExecution
class AuditLogShipperJob(private val useCase: RunAuditLogShipperUseCase) : Job {
    private val logger = LoggerFactory.getLogger(AuditLogShipperJob::class.java)

    override fun execute(context: JobExecutionContext) {
        val summary = runBlocking { useCase.execute() }
        logger.info("AuditLogShipperJob: {}", summary::class.simpleName)
    }
}
