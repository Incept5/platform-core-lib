package org.incept5.platform.core.config.constants

/**
 * Central location for API-related constants to avoid typos and ensure consistency
 * across the codebase.
 */
object ApiConstants {

    /**
     * Supabase Auth API v1 endpoint path
     */
    const val SUPABASE_AUTH_V1_PATH = "/auth/v1"

    /**
     * Platform OAuth token endpoint path
     */
    const val PLATFORM_OAUTH_TOKEN_PATH = "/api/v1/oauth/token"

    /**
     * Common Supabase Auth API v1 sub-paths
     */
    object SupabaseAuth {
        const val ADMIN_USERS = "$SUPABASE_AUTH_V1_PATH/admin/users"
        const val INVITE = "$SUPABASE_AUTH_V1_PATH/invite"
        const val RESEND = "$SUPABASE_AUTH_V1_PATH/resend"
        const val TOKEN = "$SUPABASE_AUTH_V1_PATH/token"
    }
}
