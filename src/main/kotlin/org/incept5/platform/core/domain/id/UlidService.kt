package org.incept5.platform.core.domain.id

import jakarta.enterprise.context.ApplicationScoped

/**
 * CDI-injectable ULID generation service
 * Use this for dependency injection in services
 */
@ApplicationScoped
class UlidService : IdGenerator<String> {

    override fun generate(): String = UlidGenerator.generate()
}
