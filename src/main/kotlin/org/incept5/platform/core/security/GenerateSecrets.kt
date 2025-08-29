
package org.incept5.platform.core.security

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import java.time.Instant
import kotlin.random.Random
import kotlin.system.exitProcess
import java.util.Properties
import java.io.FileInputStream
import java.io.File

class GenerateSecrets {
    companion object {
        private fun generateRandomString(length: Int): String {
            val chars = ('A'..'Z') + ('a'..'z') + ('0'..'9')
            return (1..length)
                .map { chars[Random.nextInt(chars.size)] }
                .joinToString("")
        }

        private fun generateJwt(
            secret: String,
            role: String,
            subject: String? = null,
            issuer: String,
            issuedAt: Instant,
            expiresAt: Instant
        ): String {
            val algorithm = Algorithm.HMAC256(secret)
            val jwtBuilder = JWT.create()
                .withClaim("role", role)
                .withIssuer(issuer)
                .withIssuedAt(issuedAt)
                .withExpiresAt(expiresAt)

            // Only add subject if provided
            subject?.let { jwtBuilder.withSubject(it) }

            return jwtBuilder.sign(algorithm)
        }

        private fun promptForPrefix(): String {
            println("Enter prefix for secrets (e.g. myapp-dev): ")
            val input = readlnOrNull()
            return when {
                input.isNullOrBlank() -> {
                    println("Error: Prefix cannot be empty")
                    exitProcess(1)
                }
                else -> input
            }
        }

        private fun promptForApiBaseUrl(): String {
            println("Enter API base URL (e.g. https://api.platform.example.com): ")
            val input = readlnOrNull()
            return when {
                input.isNullOrBlank() -> {
                    println("Error: API base URL cannot be empty")
                    exitProcess(1)
                }
                else -> input.trimEnd('/')
            }
        }

        private fun getApiBaseUrlFromEnvironment(): String? {
            // Try to get from system property first (passed from gradle)
            val systemPropUrl = System.getProperty("api.base.url")
            if (!systemPropUrl.isNullOrBlank()) {
                return systemPropUrl.trimEnd('/')
            }

            // Try to get from environment variable
            val envUrl = System.getenv("API_BASE_URL")
            if (!envUrl.isNullOrBlank()) {
                return envUrl.trimEnd('/')
            }

            // Try to read from ops/config/environments/dev/.env if it exists
            val devEnvFile = File("../../ops/config/environments/dev/.env")
            if (devEnvFile.exists()) {
                try {
                    val properties = Properties()
                    devEnvFile.bufferedReader().use { reader ->
                        reader.lineSequence().forEach { line ->
                            val trimmed = line.trim()
                            if (trimmed.isNotEmpty() && !trimmed.startsWith("#") && trimmed.contains("=")) {
                                val parts = trimmed.split("=", limit = 2)
                                if (parts.size == 2) {
                                    properties[parts[0].trim()] = parts[1].trim()
                                }
                            }
                        }
                    }
                    val apiBaseUrl = properties.getProperty("API_BASE_URL")
                    if (!apiBaseUrl.isNullOrBlank()) {
                        return apiBaseUrl.trimEnd('/')
                    }
                } catch (e: Exception) {
                    // Ignore errors reading the file
                }
            }

            return null
        }

        @JvmStatic
        fun main(args: Array<String>) {
            val prefix = args.getOrNull(0)?.takeIf { it.isNotBlank() }
                ?: promptForPrefix()

            val apiBaseUrl = args.getOrNull(1)?.takeIf { it.isNotBlank() }
                ?: getApiBaseUrlFromEnvironment()
                ?: promptForApiBaseUrl()

            // Generate DB password
            val dbPassword = "$prefix-db-${generateRandomString(32)}"
            println("TF_VAR_db_password --> $dbPassword")

            // Generate JWT secret
            val jwtSecret = "$prefix-jwt-${generateRandomString(32)}"
            println("TF_VAR_jwt_secret --> $jwtSecret")

            // Calculate timestamps
            val now = Instant.now()
            val tenYears = now.plusSeconds(315360000)

            // Construct the full issuer URL
            val issuer = "$apiBaseUrl/auth/v1"

            // Generate anon JWT (without subject claim)
            val anonJwt = generateJwt(
                secret = jwtSecret,
                role = "anon",
                issuer = issuer,
                issuedAt = now,
                expiresAt = tenYears
            )
            println("TF_VAR_anon_key --> $anonJwt")

            // Generate service role JWT
            val serviceJwt = generateJwt(
                secret = jwtSecret,
                role = "service_role",
                subject = "service-role",
                issuer = issuer,
                issuedAt = now,
                expiresAt = tenYears
            )
            println("TF_VAR_service_role_key --> $serviceJwt")
        }
    }
}
