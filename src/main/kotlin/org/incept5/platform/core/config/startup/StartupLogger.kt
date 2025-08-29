package org.incept5.platform.core.config.startup

import io.quarkus.runtime.StartupEvent
import jakarta.enterprise.context.ApplicationScoped
import jakarta.enterprise.event.Observes
import org.eclipse.microprofile.config.inject.ConfigProperty
import org.jboss.logging.Logger
import java.util.*

@ApplicationScoped
class StartupLogger {

    @ConfigProperty(name = "quarkus.application.name", defaultValue = "Platform Application")
    lateinit var applicationName: String

    @ConfigProperty(name = "quarkus.application.version", defaultValue = "unknown")
    lateinit var applicationVersion: String

    @ConfigProperty(name = "quarkus.profile", defaultValue = "unknown")
    lateinit var profile: String

    private val log: Logger = Logger.getLogger(StartupLogger::class.java)

    fun onStart(@Observes event: StartupEvent) {
        val javaVersion = System.getProperty("java.version")
        val javaVendor = System.getProperty("java.vendor")

        log.info("================================")
        log.info("Starting $applicationName")
        log.info("Version: $applicationVersion")
        log.info("Profile: $profile")
        log.info("Java: $javaVersion ($javaVendor)")
        log.info("Timezone: ${TimeZone.getDefault().id}")
        log.info("================================")
    }
}
