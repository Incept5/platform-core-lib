package org.incept5.platform.core.security

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import com.github.tomakehurst.wiremock.client.WireMock.aResponse
import com.github.tomakehurst.wiremock.client.WireMock.get
import com.github.tomakehurst.wiremock.client.WireMock.stubFor
import com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo
import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo
import com.github.tomakehurst.wiremock.junit5.WireMockTest
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.collections.shouldContainExactly
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import org.junit.jupiter.api.Test
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.time.Instant
import java.util.Base64
import java.util.Date

@WireMockTest
class SingleIssuerJwtValidatorTest {

    private val issuer = "chivo-1.1"
    private val audience = "wallet-api"
    private val jwksPath = "/.well-known/jwks.json"

    // --- Happy paths ---

    @Test
    fun `verify accepts a valid session token and extracts chivo claims`(wm: WireMockRuntimeInfo) {
        val kp = generateKeyPair()
        val kid = "key-1"
        stubJwks(wm, listOf(JwkEntry(kid, kp.public as RSAPublicKey)))

        val token = JWT.create()
            .withKeyId(kid)
            .withIssuer(issuer)
            .withAudience(audience)
            .withSubject("01HXYZUSER")
            .withClaim("sub_type", "personal")
            .withClaim("kyc_level", 2)
            .withClaim("device_id", "01HXYZDEV")
            .withClaim("scopes", listOf("wallet:read", "wallet:transfer"))
            .withJWTId("01HXYZJTI")
            .withIssuedAt(Date.from(Instant.now()))
            .withExpiresAt(Date.from(Instant.now().plusSeconds(900)))
            .sign(rsa(kp))

        val claims = validator(wm).verify(token)

        claims.subject shouldBe "01HXYZUSER"
        claims.subjectType shouldBe "personal"
        claims.kycLevel shouldBe 2
        claims.deviceId shouldBe "01HXYZDEV"
        claims.scopes shouldContainExactly listOf("wallet:read", "wallet:transfer")
        claims.jti shouldBe "01HXYZJTI"
        claims.issuer shouldBe issuer
        claims.audience shouldContainExactly listOf(audience)
        claims.purpose shouldBe null
        claims.purposeContext shouldBe null
    }

    @Test
    fun `verify accepts a minimal valid token without optional chivo claims`(wm: WireMockRuntimeInfo) {
        val kp = generateKeyPair()
        val kid = "key-1"
        stubJwks(wm, listOf(JwkEntry(kid, kp.public as RSAPublicKey)))

        val token = JWT.create()
            .withKeyId(kid)
            .withIssuer(issuer)
            .withAudience(audience)
            .withSubject("user-min")
            .withIssuedAt(Date.from(Instant.now()))
            .withExpiresAt(Date.from(Instant.now().plusSeconds(900)))
            .sign(rsa(kp))

        val claims = validator(wm).verify(token)

        claims.subject shouldBe "user-min"
        claims.subjectType shouldBe null
        claims.kycLevel shouldBe null
        claims.deviceId shouldBe null
        claims.scopes shouldBe emptyList()
    }

    @Test
    fun `verify selects the right key when JWKS rotates two kids`(wm: WireMockRuntimeInfo) {
        val previous = generateKeyPair()
        val current = generateKeyPair()
        stubJwks(
            wm,
            listOf(
                JwkEntry("previous", previous.public as RSAPublicKey),
                JwkEntry("current", current.public as RSAPublicKey)
            )
        )

        val tokenSignedByPrevious = JWT.create()
            .withKeyId("previous")
            .withIssuer(issuer)
            .withAudience(audience)
            .withSubject("user-prev")
            .withIssuedAt(Date.from(Instant.now()))
            .withExpiresAt(Date.from(Instant.now().plusSeconds(900)))
            .sign(rsa(previous))

        val tokenSignedByCurrent = JWT.create()
            .withKeyId("current")
            .withIssuer(issuer)
            .withAudience(audience)
            .withSubject("user-curr")
            .withIssuedAt(Date.from(Instant.now()))
            .withExpiresAt(Date.from(Instant.now().plusSeconds(900)))
            .sign(rsa(current))

        val v = validator(wm)
        v.verify(tokenSignedByPrevious).subject shouldBe "user-prev"
        v.verify(tokenSignedByCurrent).subject shouldBe "user-curr"
    }

    // --- Step-up ---

    @Test
    fun `verifyStepUp accepts a token whose purpose and context match`(wm: WireMockRuntimeInfo) {
        val kp = generateKeyPair()
        stubJwks(wm, listOf(JwkEntry("k", kp.public as RSAPublicKey)))

        val token = JWT.create()
            .withKeyId("k")
            .withIssuer(issuer)
            .withAudience(audience)
            .withSubject("user-1")
            .withClaim("purpose", "transfer")
            .withClaim("purpose_context", mapOf("transfer_id" to "01HXYZTX", "amount" to 1000))
            .withIssuedAt(Date.from(Instant.now()))
            .withExpiresAt(Date.from(Instant.now().plusSeconds(60)))
            .sign(rsa(kp))

        val claims = validator(wm).verifyStepUp(
            token,
            expectedPurpose = "transfer",
            expectedContext = mapOf("transfer_id" to "01HXYZTX", "amount" to 1000)
        )

        claims.purpose shouldBe "transfer"
        claims.purposeContext?.get("transfer_id").toString() shouldBe "01HXYZTX"
    }

    @Test
    fun `verifyStepUp rejects a token with mismatched purpose`(wm: WireMockRuntimeInfo) {
        val kp = generateKeyPair()
        stubJwks(wm, listOf(JwkEntry("k", kp.public as RSAPublicKey)))

        val token = stepUpToken(kp, purpose = "withdraw", context = mapOf("transfer_id" to "x"))

        val ex = shouldThrow<UnknownTokenException> {
            validator(wm).verifyStepUp(token, expectedPurpose = "transfer", expectedContext = mapOf("transfer_id" to "x"))
        }
        ex.message shouldContain "Step-up purpose mismatch"
    }

    @Test
    fun `verifyStepUp rejects a token whose context value does not match`(wm: WireMockRuntimeInfo) {
        val kp = generateKeyPair()
        stubJwks(wm, listOf(JwkEntry("k", kp.public as RSAPublicKey)))

        val token = stepUpToken(kp, purpose = "transfer", context = mapOf("transfer_id" to "01HXYZ-OLD"))

        val ex = shouldThrow<UnknownTokenException> {
            validator(wm).verifyStepUp(
                token,
                expectedPurpose = "transfer",
                expectedContext = mapOf("transfer_id" to "01HXYZ-NEW")
            )
        }
        ex.message shouldContain "purpose_context mismatch"
    }

    @Test
    fun `verifyStepUp rejects a token missing a required context key`(wm: WireMockRuntimeInfo) {
        val kp = generateKeyPair()
        stubJwks(wm, listOf(JwkEntry("k", kp.public as RSAPublicKey)))

        val token = stepUpToken(kp, purpose = "transfer", context = mapOf("amount" to 1000))

        val ex = shouldThrow<UnknownTokenException> {
            validator(wm).verifyStepUp(
                token,
                expectedPurpose = "transfer",
                expectedContext = mapOf("transfer_id" to "01HXYZ")
            )
        }
        ex.message shouldContain "purpose_context mismatch on 'transfer_id'"
    }

    @Test
    fun `verifyStepUp rejects a token missing the purpose claim`(wm: WireMockRuntimeInfo) {
        val kp = generateKeyPair()
        stubJwks(wm, listOf(JwkEntry("k", kp.public as RSAPublicKey)))

        // A valid session-style token, but with no purpose claim
        val token = JWT.create()
            .withKeyId("k")
            .withIssuer(issuer)
            .withAudience(audience)
            .withSubject("user-1")
            .withIssuedAt(Date.from(Instant.now()))
            .withExpiresAt(Date.from(Instant.now().plusSeconds(60)))
            .sign(rsa(kp))

        val ex = shouldThrow<UnknownTokenException> {
            validator(wm).verifyStepUp(token, expectedPurpose = "transfer")
        }
        ex.message shouldContain "missing 'purpose' claim"
    }

    // --- Rejection cases ---

    @Test
    fun `verify rejects a token with the wrong issuer`(wm: WireMockRuntimeInfo) {
        val kp = generateKeyPair()
        stubJwks(wm, listOf(JwkEntry("k", kp.public as RSAPublicKey)))

        val token = JWT.create()
            .withKeyId("k")
            .withIssuer("somebody-else")
            .withAudience(audience)
            .withSubject("user-1")
            .withIssuedAt(Date.from(Instant.now()))
            .withExpiresAt(Date.from(Instant.now().plusSeconds(900)))
            .sign(rsa(kp))

        val ex = shouldThrow<UnknownTokenException> { validator(wm).verify(token) }
        ex.message shouldContain "Invalid issuer"
    }

    @Test
    fun `verify rejects a token with the wrong audience`(wm: WireMockRuntimeInfo) {
        val kp = generateKeyPair()
        stubJwks(wm, listOf(JwkEntry("k", kp.public as RSAPublicKey)))

        val token = JWT.create()
            .withKeyId("k")
            .withIssuer(issuer)
            .withAudience("merchant-api")
            .withSubject("user-1")
            .withIssuedAt(Date.from(Instant.now()))
            .withExpiresAt(Date.from(Instant.now().plusSeconds(900)))
            .sign(rsa(kp))

        shouldThrow<UnknownTokenException> { validator(wm).verify(token) }
    }

    @Test
    fun `verify rejects an expired token outside the leeway window`(wm: WireMockRuntimeInfo) {
        val kp = generateKeyPair()
        stubJwks(wm, listOf(JwkEntry("k", kp.public as RSAPublicKey)))

        val token = JWT.create()
            .withKeyId("k")
            .withIssuer(issuer)
            .withAudience(audience)
            .withSubject("user-1")
            .withIssuedAt(Date.from(Instant.now().minusSeconds(7200)))
            .withExpiresAt(Date.from(Instant.now().minusSeconds(3600)))
            .sign(rsa(kp))

        shouldThrow<UnknownTokenException> { validator(wm).verify(token) }
    }

    @Test
    fun `verify rejects a token signed by an unknown kid`(wm: WireMockRuntimeInfo) {
        val served = generateKeyPair()
        val attacker = generateKeyPair()
        stubJwks(wm, listOf(JwkEntry("served-kid", served.public as RSAPublicKey)))

        val token = JWT.create()
            .withKeyId("attacker-kid")
            .withIssuer(issuer)
            .withAudience(audience)
            .withSubject("user-1")
            .withIssuedAt(Date.from(Instant.now()))
            .withExpiresAt(Date.from(Instant.now().plusSeconds(900)))
            .sign(rsa(attacker))

        val ex = shouldThrow<UnknownTokenException> { validator(wm).verify(token) }
        ex.message shouldContain "Public key not found"
    }

    @Test
    fun `verify rejects a token whose signature does not match the served public key`(wm: WireMockRuntimeInfo) {
        val served = generateKeyPair()
        val attacker = generateKeyPair()
        // Attacker signs with their own key but claims the legitimate kid
        stubJwks(wm, listOf(JwkEntry("k", served.public as RSAPublicKey)))

        val token = JWT.create()
            .withKeyId("k")
            .withIssuer(issuer)
            .withAudience(audience)
            .withSubject("user-1")
            .withIssuedAt(Date.from(Instant.now()))
            .withExpiresAt(Date.from(Instant.now().plusSeconds(900)))
            .sign(rsa(attacker))

        shouldThrow<UnknownTokenException> { validator(wm).verify(token) }
    }

    @Test
    fun `verify rejects a malformed token`(wm: WireMockRuntimeInfo) {
        val kp = generateKeyPair()
        stubJwks(wm, listOf(JwkEntry("k", kp.public as RSAPublicKey)))

        val ex = shouldThrow<UnknownTokenException> {
            validator(wm).verify("not.a.jwt")
        }
        ex.message shouldContain "Invalid token format"
    }

    // --- Helpers ---

    private data class JwkEntry(val kid: String, val publicKey: RSAPublicKey)

    private fun stubJwks(wm: WireMockRuntimeInfo, keys: List<JwkEntry>) {
        val keyEntries = keys.joinToString(",") { entry ->
            val n = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(entry.publicKey.modulus.toByteArray())
            val e = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(entry.publicKey.publicExponent.toByteArray())
            """{"kid":"${entry.kid}","kty":"RSA","use":"sig","n":"$n","e":"$e"}"""
        }
        val body = """{"keys":[$keyEntries]}"""
        stubFor(
            get(urlEqualTo(jwksPath)).willReturn(
                aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "application/json")
                    .withBody(body)
            )
        )
    }

    private fun validator(wm: WireMockRuntimeInfo): SingleIssuerJwtValidator =
        SingleIssuerJwtValidator(
            issuer = issuer,
            audience = audience,
            jwksUrl = "${wm.httpBaseUrl}$jwksPath",
            leewaySeconds = 0L
        )

    private fun rsa(kp: KeyPair): Algorithm =
        Algorithm.RSA256(kp.public as RSAPublicKey, kp.private as RSAPrivateKey)

    private fun generateKeyPair(): KeyPair {
        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.initialize(2048)
        return kpg.generateKeyPair()
    }

    private fun stepUpToken(
        kp: KeyPair,
        purpose: String,
        context: Map<String, Any>
    ): String =
        JWT.create()
            .withKeyId("k")
            .withIssuer(issuer)
            .withAudience(audience)
            .withSubject("user-1")
            .withClaim("purpose", purpose)
            .withClaim("purpose_context", context)
            .withIssuedAt(Date.from(Instant.now()))
            .withExpiresAt(Date.from(Instant.now().plusSeconds(60)))
            .sign(rsa(kp))
}
