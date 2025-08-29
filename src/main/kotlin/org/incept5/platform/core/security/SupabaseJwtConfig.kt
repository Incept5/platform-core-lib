
package org.incept5.platform.core.security

import io.quarkus.runtime.annotations.StaticInitSafe
import io.smallrye.config.ConfigMapping
import io.smallrye.config.WithDefault
import io.smallrye.config.WithName

@ConfigMapping(prefix = "supabase.jwt")
@StaticInitSafe
interface SupabaseJwtConfig {
    @WithName("secret")
    fun secret(): String
}
