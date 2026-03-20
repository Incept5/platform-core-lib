package org.incept5.platform.core.authz
import org.incept5.platform.core.model.EntityType
import org.incept5.platform.core.model.UserRole

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldContainExactly
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import org.incept5.platform.core.security.DualJwtValidator
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.Instant
import java.util.*

class SupabaseTokenExchangePluginTest {

    private lateinit var plugin: SupabaseTokenExchangePlugin
    private lateinit var dualJwtValidator: DualJwtValidator

    private val jwtSecretBytes = "test-secret-key-that-is-long-enough-for-hmac256-algorithm".toByteArray()
    private val jwtSecret = Base64.getEncoder().encodeToString(jwtSecretBytes)
    private val baseApiUrl = "https://api.test.com"
    private val supabaseAuthPath = "/auth/v1"
    private val platformOauthPath = "/api/v1/oauth/token"
    private val algorithm = Algorithm.HMAC256(jwtSecretBytes)

    @BeforeEach
    fun setup() {
        dualJwtValidator = DualJwtValidator(
            jwtSecret = jwtSecret,
            hmacFallbackEnabled = true,
            baseApiUrl = baseApiUrl,
            supabaseAuthPath = supabaseAuthPath,
            platformOauthPath = platformOauthPath,
            rsaPublicKey = Optional.empty(),
            jwksUrl = Optional.empty()
        )
        plugin = SupabaseTokenExchangePlugin(dualJwtValidator)
    }

    @Test
    fun `exchangeToken returns ApiPrincipal with all token fields`() {
        val subject = UUID.randomUUID().toString()
        val partnerId = "P1"
        val token = createPlatformToken(
            subject = subject,
            role = "entity_admin",
            entityType = "partner",
            entityId = partnerId,
            scopes = listOf("read", "write")
        )

        val result = plugin.exchangeToken(token)

        result.shouldNotBeNull()
        result.shouldBeInstanceOf<ApiPrincipal>()
        val apiPrincipal = result as ApiPrincipal
        apiPrincipal.subject shouldBe subject
        apiPrincipal.userRole.value shouldBe "entity_admin"
        apiPrincipal.entityType shouldBe EntityType.PARTNER
        apiPrincipal.entityId shouldBe partnerId
        apiPrincipal.scopes.shouldContainExactly("read", "write")
        apiPrincipal.name shouldBe subject
    }

    // AC4: Platform admin maps to backoffice.admin
    @Test
    fun `platform_admin maps to backoffice admin with no entity roles`() {
        val subject = UUID.randomUUID().toString()
        val token = createSupabaseToken(subject, "platform_admin")

        val result = plugin.exchangeToken(token)

        result.shouldNotBeNull()
        result.getPrincipalId() shouldBe UUID.fromString(subject)
        result.getGlobalRoles().shouldContainExactly("backoffice.admin")
        result.getEntityRoles().shouldBeEmpty()
    }

    // AC5: Service role maps to service.admin
    @Test
    fun `service_role maps to service admin with no entity roles`() {
        val token = createSupabaseToken(
            subject = UUID.randomUUID().toString(),
            role = "service_role"
        )

        val result = plugin.exchangeToken(token)

        result.shouldNotBeNull()
        result.getGlobalRoles().shouldContainExactly("service.admin")
        result.getEntityRoles().shouldBeEmpty()
    }

    // AC2: entity_admin + partner maps to partner.admin
    @Test
    fun `entity_admin with partner maps to partner admin with entity role`() {
        val subject = UUID.randomUUID().toString()
        val partnerId = "P1"
        val token = createSupabaseToken(
            subject = subject,
            role = "entity_admin",
            entityType = "partner",
            entityId = partnerId
        )

        val result = plugin.exchangeToken(token)

        result.shouldNotBeNull()
        result.getPrincipalId() shouldBe UUID.fromString(subject)
        result.getGlobalRoles().shouldContainExactly("partner.admin")
        result.getEntityRoles().shouldHaveSize(1)
        result.getEntityRoles()[0].let { entityRole ->
            entityRole.type shouldBe "partner"
            entityRole.roles.shouldContainExactly("partner.admin")
            entityRole.ids.shouldContainExactly(partnerId)
        }
    }

    // AC2 variant: entity_admin + merchant maps to merchant.admin
    @Test
    fun `entity_admin with merchant maps to merchant admin with entity role`() {
        val subject = UUID.randomUUID().toString()
        val merchantId = "M1"
        val token = createSupabaseToken(
            subject = subject,
            role = "entity_admin",
            entityType = "merchant",
            entityId = merchantId
        )

        val result = plugin.exchangeToken(token)

        result.shouldNotBeNull()
        result.getGlobalRoles().shouldContainExactly("merchant.admin")
        result.getEntityRoles().shouldHaveSize(1)
        result.getEntityRoles()[0].let { entityRole ->
            entityRole.type shouldBe "merchant"
            entityRole.roles.shouldContainExactly("merchant.admin")
            entityRole.ids.shouldContainExactly(merchantId)
        }
    }

    // AC3: entity_user + partner maps to partner.user
    @Test
    fun `entity_user with partner maps to partner user with entity role`() {
        val subject = UUID.randomUUID().toString()
        val partnerId = "P1"
        val token = createSupabaseToken(
            subject = subject,
            role = "entity_user",
            entityType = "partner",
            entityId = partnerId
        )

        val result = plugin.exchangeToken(token)

        result.shouldNotBeNull()
        result.getGlobalRoles().shouldContainExactly("partner.user")
        result.getEntityRoles().shouldHaveSize(1)
        result.getEntityRoles()[0].let { entityRole ->
            entityRole.type shouldBe "partner"
            entityRole.roles.shouldContainExactly("partner.user")
            entityRole.ids.shouldContainExactly(partnerId)
        }
    }

    // AC3: entity_user + merchant maps to merchant.user
    @Test
    fun `entity_user with merchant maps to merchant user with entity role`() {
        val subject = UUID.randomUUID().toString()
        val merchantId = "M1"
        val token = createSupabaseToken(
            subject = subject,
            role = "entity_user",
            entityType = "merchant",
            entityId = merchantId
        )

        val result = plugin.exchangeToken(token)

        result.shouldNotBeNull()
        result.getGlobalRoles().shouldContainExactly("merchant.user")
        result.getEntityRoles().shouldHaveSize(1)
        result.getEntityRoles()[0].let { entityRole ->
            entityRole.type shouldBe "merchant"
            entityRole.roles.shouldContainExactly("merchant.user")
            entityRole.ids.shouldContainExactly(merchantId)
        }
    }

    // entity_readonly maps to user role (readonly differentiation via permissions, not roles)
    @Test
    fun `entity_readonly with partner maps to partner user with entity role`() {
        val subject = UUID.randomUUID().toString()
        val partnerId = "P1"
        val token = createSupabaseToken(
            subject = subject,
            role = "entity_readonly",
            entityType = "partner",
            entityId = partnerId
        )

        val result = plugin.exchangeToken(token)

        result.shouldNotBeNull()
        result.getGlobalRoles().shouldContainExactly("partner.user")
        result.getEntityRoles().shouldHaveSize(1)
        result.getEntityRoles()[0].let { entityRole ->
            entityRole.type shouldBe "partner"
            entityRole.roles.shouldContainExactly("partner.user")
            entityRole.ids.shouldContainExactly(partnerId)
        }
    }

    @Test
    fun `entity_readonly with merchant maps to merchant user with entity role`() {
        val subject = UUID.randomUUID().toString()
        val merchantId = "M1"
        val token = createSupabaseToken(
            subject = subject,
            role = "entity_readonly",
            entityType = "merchant",
            entityId = merchantId
        )

        val result = plugin.exchangeToken(token)

        result.shouldNotBeNull()
        result.getGlobalRoles().shouldContainExactly("merchant.user")
        result.getEntityRoles().shouldHaveSize(1)
        result.getEntityRoles()[0].let { entityRole ->
            entityRole.type shouldBe "merchant"
            entityRole.roles.shouldContainExactly("merchant.user")
            entityRole.ids.shouldContainExactly(merchantId)
        }
    }

    // AC6: Invalid token returns null
    @Test
    fun `invalid token returns null`() {
        val result = plugin.exchangeToken("invalid.token.here")

        result.shouldBeNull()
    }

    @Test
    fun `expired token returns null`() {
        val token = JWT.create()
            .withSubject(UUID.randomUUID().toString())
            .withClaim("role", "platform_admin")
            .withIssuer("$baseApiUrl$supabaseAuthPath")
            .withExpiresAt(Instant.now().minusSeconds(3600))
            .sign(algorithm)

        val result = plugin.exchangeToken(token)

        result.shouldBeNull()
    }

    // AC9: entity_admin with null entityType has no entity roles
    @Test
    fun `entity_admin with null entityType has global role but no entity roles`() {
        val subject = UUID.randomUUID().toString()
        val token = createSupabaseToken(
            subject = subject,
            role = "entity_admin"
        )

        val result = plugin.exchangeToken(token)

        result.shouldNotBeNull()
        result.getGlobalRoles().shouldContainExactly("partner.user")
        result.getEntityRoles().shouldBeEmpty()
    }

    // AC10: Platform token (client credentials) maps correctly
    @Test
    fun `platform token with entity_admin role maps correctly`() {
        val subject = UUID.randomUUID().toString()
        val partnerId = "P1"
        val token = createPlatformToken(
            subject = subject,
            role = "entity_admin",
            entityType = "partner",
            entityId = partnerId
        )

        val result = plugin.exchangeToken(token)

        result.shouldNotBeNull()
        result.getPrincipalId() shouldBe UUID.fromString(subject)
        result.getGlobalRoles().shouldContainExactly("partner.admin")
        result.getEntityRoles().shouldHaveSize(1)
        result.getEntityRoles()[0].let { entityRole ->
            entityRole.type shouldBe "partner"
            entityRole.roles.shouldContainExactly("partner.admin")
            entityRole.ids.shouldContainExactly(partnerId)
        }
    }

    // --- Role mapping unit tests (via plugin.mapRole) ---

    @Test
    fun `mapRole covers all legacy role and entity type combinations`() {
        // Platform-level roles
        plugin.mapRole("platform_admin", null) shouldBe "backoffice.admin"
        plugin.mapRole("service_role", null) shouldBe "service.admin"

        // Partner entity roles
        plugin.mapRole("entity_admin", EntityType.PARTNER) shouldBe "partner.admin"
        plugin.mapRole("entity_user", EntityType.PARTNER) shouldBe "partner.user"
        plugin.mapRole("entity_readonly", EntityType.PARTNER) shouldBe "partner.user"

        // Merchant entity roles
        plugin.mapRole("entity_admin", EntityType.MERCHANT) shouldBe "merchant.admin"
        plugin.mapRole("entity_user", EntityType.MERCHANT) shouldBe "merchant.user"
        plugin.mapRole("entity_readonly", EntityType.MERCHANT) shouldBe "merchant.user"

        // Fallback for null entity type on entity roles
        plugin.mapRole("entity_admin", null) shouldBe "partner.user"
        plugin.mapRole("entity_user", null) shouldBe "partner.user"
        plugin.mapRole("entity_readonly", null) shouldBe "partner.user"

        // New role names pass through
        plugin.mapRole("backoffice.admin", null) shouldBe "backoffice.admin"
        plugin.mapRole("partner.admin", null) shouldBe "partner.admin"
    }

    /**
     * Demonstrates how legacy JWT roles map to the authz-lib role names
     * used in the fanfair services role configuration:
     *
     * backoffice.admin  -> ".*:all" (full access)
     * partner.admin     -> extends partner.user + partner:update, merchant:create, user:all, apikey:all, etc.
     * partner.user      -> partner:read, merchant:read, payment:read/create, settlement:read, etc.
     * merchant.admin    -> extends merchant.user + merchant:update, user:all, webhook:all, apikey:all, etc.
     * merchant.user     -> merchant:read, payment:read/create, settlement:read, etc.
     *
     * The role hierarchy means:
     *   partner.admin has all partner.user permissions PLUS additional admin permissions
     *   merchant.admin has all merchant.user permissions PLUS additional admin permissions
     */
    @Test
    fun `legacy JWT roles map to fanfair authz-lib role hierarchy`() {
        // A platform_admin JWT becomes backoffice.admin which has wildcard ".*:all" access
        plugin.mapRole("platform_admin", null) shouldBe "backoffice.admin"

        // An entity_admin for a partner becomes partner.admin
        // which extends partner.user and adds partner:update, merchant:create/update/delete,
        // user:create/read/update/delete, apikey:all, webhook:all, gateway:all, etc.
        plugin.mapRole("entity_admin", EntityType.PARTNER) shouldBe "partner.admin"

        // An entity_user for a partner becomes partner.user
        // which has read-only style permissions: partner:read, merchant:read, payment:read/create, etc.
        plugin.mapRole("entity_user", EntityType.PARTNER) shouldBe "partner.user"

        // An entity_admin for a merchant becomes merchant.admin
        // which extends merchant.user and adds merchant:update, user:create/read/update/delete,
        // webhook:all, apikey:all, etc.
        plugin.mapRole("entity_admin", EntityType.MERCHANT) shouldBe "merchant.admin"

        // An entity_user for a merchant becomes merchant.user
        // which has: merchant:read, payment:read/create, settlement:read, payout:read, etc.
        plugin.mapRole("entity_user", EntityType.MERCHANT) shouldBe "merchant.user"

        // entity_readonly maps to the base user role (readonly is handled via permissions, not role names)
        plugin.mapRole("entity_readonly", EntityType.PARTNER) shouldBe "partner.user"
        plugin.mapRole("entity_readonly", EntityType.MERCHANT) shouldBe "merchant.user"

        // New-style role names (already matching authz-lib config) pass through unchanged
        plugin.mapRole("backoffice.admin", null) shouldBe "backoffice.admin"
        plugin.mapRole("partner.admin", EntityType.PARTNER) shouldBe "partner.admin"
        plugin.mapRole("merchant.user", EntityType.MERCHANT) shouldBe "merchant.user"
    }

    @Test
    fun `full token exchange produces roles matching fanfair config hierarchy`() {
        // Simulate a partner admin user logging in with a legacy Supabase token
        val subject = UUID.randomUUID().toString()
        val partnerId = "PARTNER-123"
        val token = createSupabaseToken(
            subject = subject,
            role = "entity_admin",
            entityType = "partner",
            entityId = partnerId
        )

        val result = plugin.exchangeToken(token)

        // The principal gets partner.admin as global role
        // In authz-lib config, partner.admin extends partner.user and can assign partner.user and merchant.admin
        result.shouldNotBeNull()
        result.getGlobalRoles().shouldContainExactly("partner.admin")
        result.getEntityRoles().shouldHaveSize(1)
        result.getEntityRoles()[0].let { entityRole ->
            entityRole.type shouldBe "partner"
            entityRole.roles.shouldContainExactly("partner.admin")
            entityRole.ids.shouldContainExactly(partnerId)
        }

        // Now simulate the same user with the new-style role name (no legacy mapping needed)
        val newStyleToken = createSupabaseToken(
            subject = subject,
            role = "partner.admin",
            entityType = "partner",
            entityId = partnerId
        )

        val newStyleResult = plugin.exchangeToken(newStyleToken)

        // Both legacy and new-style tokens produce the same principal roles
        newStyleResult.shouldNotBeNull()
        newStyleResult.getGlobalRoles().shouldContainExactly("partner.admin")
        newStyleResult.getEntityRoles()[0].roles.shouldContainExactly("partner.admin")
    }

    // --- Helper methods ---

    private fun createSupabaseToken(
        subject: String,
        role: String,
        entityType: String? = null,
        entityId: String? = null
    ): String {
        val builder = JWT.create()
            .withSubject(subject)
            .withClaim("role", role)
            .withIssuer("$baseApiUrl$supabaseAuthPath")
            .withIssuedAt(Instant.now())
            .withExpiresAt(Instant.now().plusSeconds(3600))

        if (entityType != null || entityId != null) {
            val appMetadata = mutableMapOf<String, Any>()
            entityType?.let { appMetadata["entity_type"] = it }
            entityId?.let { appMetadata["entity_id"] = it }
            builder.withClaim("app_metadata", appMetadata)
        }

        return builder.sign(algorithm)
    }

    private fun createPlatformToken(
        subject: String,
        role: String,
        entityType: String? = null,
        entityId: String? = null,
        scopes: List<String> = emptyList()
    ): String {
        val builder = JWT.create()
            .withSubject(subject)
            .withClaim("role", role)
            .withIssuer("$baseApiUrl$platformOauthPath")
            .withIssuedAt(Instant.now())
            .withExpiresAt(Instant.now().plusSeconds(3600))

        if (scopes.isNotEmpty()) {
            builder.withClaim("scopes", scopes)
        }

        if (entityType != null || entityId != null) {
            val appMetadata = mutableMapOf<String, Any>()
            entityType?.let { appMetadata["entity_type"] = it }
            entityId?.let { appMetadata["entity_id"] = it }
            builder.withClaim("app_metadata", appMetadata)
        }

        return builder.sign(algorithm)
    }
}
