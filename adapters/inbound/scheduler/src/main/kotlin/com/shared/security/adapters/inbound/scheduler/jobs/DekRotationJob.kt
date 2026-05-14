package com.shared.security.adapters.inbound.scheduler.jobs

import com.shared.security.application.usecases.RunDekRotationUseCase
import kotlinx.coroutines.runBlocking
import org.quartz.DisallowConcurrentExecution
import org.quartz.Job
import org.quartz.JobExecutionContext
import org.slf4j.LoggerFactory

@DisallowConcurrentExecution
class DekRotationJob(private val useCase: RunDekRotationUseCase) : Job {
    private val logger = LoggerFactory.getLogger(DekRotationJob::class.java)

    override fun execute(context: JobExecutionContext) {
        val summary = runBlocking { useCase.execute() }
        logger.info("DekRotationJob: {}", summary::class.simpleName)
    }
}
