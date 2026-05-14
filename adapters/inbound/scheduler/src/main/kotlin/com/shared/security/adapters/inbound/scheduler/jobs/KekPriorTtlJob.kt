package com.shared.security.adapters.inbound.scheduler.jobs

import com.shared.security.application.usecases.RunKekPriorTtlUseCase
import kotlinx.coroutines.runBlocking
import org.quartz.DisallowConcurrentExecution
import org.quartz.Job
import org.quartz.JobExecutionContext
import org.slf4j.LoggerFactory

@DisallowConcurrentExecution
class KekPriorTtlJob(private val useCase: RunKekPriorTtlUseCase) : Job {
    private val logger = LoggerFactory.getLogger(KekPriorTtlJob::class.java)

    override fun execute(context: JobExecutionContext) {
        val summary = runBlocking { useCase.execute() }
        logger.info(
            "KekPriorTtlJob: candidates={} retired={} blockedByDeks={} blockedByTtl={}",
            summary.candidatesEvaluated,
            summary.retired,
            summary.blockedByDeks,
            summary.blockedByTtl,
        )
    }
}
