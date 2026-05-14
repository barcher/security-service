package com.shared.security.adapters.inbound.scheduler

import com.shared.security.adapters.inbound.scheduler.jobs.AuditLogShipperJob
import com.shared.security.adapters.inbound.scheduler.jobs.AuditRetentionJob
import com.shared.security.adapters.inbound.scheduler.jobs.DekRotationJob
import com.shared.security.adapters.inbound.scheduler.jobs.KekBackupVerifyJob
import com.shared.security.adapters.inbound.scheduler.jobs.KekPriorTtlJob
import com.shared.security.adapters.inbound.scheduler.jobs.KekRotationHealthJob
import com.shared.security.application.usecases.RunAuditLogShipperUseCase
import com.shared.security.application.usecases.RunAuditRetentionUseCase
import com.shared.security.application.usecases.RunDekRotationUseCase
import com.shared.security.application.usecases.RunKekBackupVerifyUseCase
import com.shared.security.application.usecases.RunKekHealthCheckUseCase
import com.shared.security.application.usecases.RunKekPriorTtlUseCase
import org.quartz.JobBuilder.newJob
import org.quartz.JobDetail
import org.quartz.Scheduler
import org.quartz.SimpleScheduleBuilder.simpleSchedule
import org.quartz.TriggerBuilder.newTrigger
import org.quartz.impl.StdSchedulerFactory
import org.quartz.spi.JobFactory
import org.quartz.spi.TriggerFiredBundle
import org.slf4j.LoggerFactory

/**
 * Owns the Quartz scheduler instance and registers every security-service job under the
 * intervals declared in [SchedulerConfig]. A no-arg start/stop interface so the composition
 * root can call it without knowing about Quartz directly.
 *
 * The custom [JobFactory] resolves Job instances from a static registry that the
 * composition root populates with use cases — this avoids both Koin-from-Quartz lookups
 * (which would create a leaky dependency from `:adapters:inbound:scheduler` to Koin) and
 * JobDataMap serialization issues (we never persist Quartz state).
 */
class SecurityScheduler(
    private val config: SchedulerConfig,
    private val useCases: UseCases,
) {
    data class UseCases(
        val kekHealth: RunKekHealthCheckUseCase,
        val kekPriorTtl: RunKekPriorTtlUseCase,
        val dekRotation: RunDekRotationUseCase,
        val auditShipper: RunAuditLogShipperUseCase,
        val auditRetention: RunAuditRetentionUseCase,
        val kekBackupVerify: RunKekBackupVerifyUseCase,
    )

    private val logger = LoggerFactory.getLogger(SecurityScheduler::class.java)
    private var scheduler: Scheduler? = null

    fun start() {
        if (!config.enabled) {
            logger.warn("SecurityScheduler is DISABLED ($${SchedulerConfig.ENV_ENABLED}=false). No jobs will fire.")
            return
        }
        logger.info("Starting SecurityScheduler with 6 jobs")
        val s = StdSchedulerFactory().scheduler
        s.setJobFactory(InjectingJobFactory(useCases))
        register(
            s,
            "KekRotationHealthJob",
            KekRotationHealthJob::class.java,
            minutes = config.kekRotationHealthIntervalMinutes,
        )
        register(s, "KekPriorTtlJob", KekPriorTtlJob::class.java, minutes = config.kekPriorTtlIntervalMinutes)
        register(s, "DekRotationJob", DekRotationJob::class.java, minutes = config.dekRotationIntervalMinutes)
        register(
            s,
            "AuditLogShipperJob",
            AuditLogShipperJob::class.java,
            minutes = config.auditLogShipperIntervalMinutes,
        )
        register(
            s,
            "AuditRetentionJob",
            AuditRetentionJob::class.java,
            minutes = config.auditRetentionIntervalHours * MIN_PER_HOUR,
        )
        register(
            s,
            "KekBackupVerifyJob",
            KekBackupVerifyJob::class.java,
            minutes = config.kekBackupVerifyIntervalHours * MIN_PER_HOUR,
        )
        s.start()
        scheduler = s
    }

    fun stop() {
        scheduler?.shutdown(true)
        scheduler = null
    }

    private fun register(
        s: Scheduler,
        name: String,
        jobClass: Class<out org.quartz.Job>,
        minutes: Int,
    ) {
        val detail: JobDetail =
            newJob(jobClass)
                .withIdentity(name, "security")
                .storeDurably(false)
                .build()
        val trigger =
            newTrigger()
                .withIdentity("${name}Trigger", "security")
                .forJob(detail)
                .withSchedule(simpleSchedule().withIntervalInMinutes(minutes).repeatForever())
                .startNow()
                .build()
        s.scheduleJob(detail, trigger)
        logger.info("Registered {} every {} minute(s)", name, minutes)
    }

    private companion object {
        const val MIN_PER_HOUR = 60
    }
}

/** Quartz [JobFactory] that constructs each Job with the use case it needs. */
internal class InjectingJobFactory(private val useCases: SecurityScheduler.UseCases) : JobFactory {
    override fun newJob(
        bundle: TriggerFiredBundle,
        scheduler: Scheduler,
    ): org.quartz.Job =
        when (val cls = bundle.jobDetail.jobClass) {
            KekRotationHealthJob::class.java -> KekRotationHealthJob(useCases.kekHealth)
            KekPriorTtlJob::class.java -> KekPriorTtlJob(useCases.kekPriorTtl)
            DekRotationJob::class.java -> DekRotationJob(useCases.dekRotation)
            AuditLogShipperJob::class.java -> AuditLogShipperJob(useCases.auditShipper)
            AuditRetentionJob::class.java -> AuditRetentionJob(useCases.auditRetention)
            KekBackupVerifyJob::class.java -> KekBackupVerifyJob(useCases.kekBackupVerify)
            else -> error("Unknown job class: ${cls.name}")
        }
}
