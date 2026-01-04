package org.incept5.platform.core.security

import com.github.tomakehurst.wiremock.client.WireMock.*
import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo
import com.github.tomakehurst.wiremock.junit5.WireMockTest
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import org.junit.jupiter.api.Test
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPublicKey
import java.util.Base64

@WireMockTest
class JwksKeyProviderTest {
    
    private fun createTestJwksProvider(wireMockRuntimeInfo: WireMockRuntimeInfo, jwksJson: String): JwksKeyProvider {
        // Stub the endpoint before creating the provider (which fetches keys in init)
        stubFor(
            get(urlEqualTo("/.well-known/jwks.json"))
                .willReturn(
                    aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody(jwksJson)
                )
        )
        
        val jwksUrl = "${wireMockRuntimeInfo.httpBaseUrl}/.well-known/jwks.json"
        return JwksKeyProvider(jwksUrl)
    }

    @Test
    fun `should parse JWKS and cache public keys`(wireMockRuntimeInfo: WireMockRuntimeInfo) {
        // Given a JWKS response with RSA keys
        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.initialize(2048)
        val kp = kpg.generateKeyPair()
        val publicKey = kp.public as RSAPublicKey
        
        val n = Base64.getUrlEncoder().withoutPadding().encodeToString(publicKey.modulus.toByteArray())
        val e = Base64.getUrlEncoder().withoutPadding().encodeToString(publicKey.publicExponent.toByteArray())
        
        val jwksJson = """
        {
          "keys": [
            {
              "kid": "test-key-1",
              "kty": "RSA",
              "use": "sig",
              "n": "$n",
              "e": "$e"
            }
          ]
        }
        """.trimIndent()
        
        // When parsing the JWKS
        val provider = createTestJwksProvider(wireMockRuntimeInfo, jwksJson)
        
        // Then should successfully retrieve the key
        val retrievedKey = provider.getPublicKeyById("test-key-1")
        retrievedKey shouldNotBe null
        retrievedKey.modulus shouldBe publicKey.modulus
        retrievedKey.publicExponent shouldBe publicKey.publicExponent
    }
    
    @Test
    fun `should return first key when key ID is null`(wireMockRuntimeInfo: WireMockRuntimeInfo) {
        // Given a JWKS with multiple keys
        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.initialize(2048)
        val kp = kpg.generateKeyPair()
        val publicKey = kp.public as RSAPublicKey
        
        val n = Base64.getUrlEncoder().withoutPadding().encodeToString(publicKey.modulus.toByteArray())
        val e = Base64.getUrlEncoder().withoutPadding().encodeToString(publicKey.publicExponent.toByteArray())
        
        val jwksJson = """
        {
          "keys": [
            {
              "kid": "key-1",
              "kty": "RSA",
              "use": "sig",
              "n": "$n",
              "e": "$e"
            }
          ]
        }
        """.trimIndent()
        
        // When requesting key with null ID
        val provider = createTestJwksProvider(wireMockRuntimeInfo, jwksJson)
        val retrievedKey = provider.getPublicKeyById(null)
        
        // Then should return the first available key
        retrievedKey shouldNotBe null
    }
    
    @Test
    fun `should throw exception when key ID not found`(wireMockRuntimeInfo: WireMockRuntimeInfo) {
        // Given a JWKS with one key
        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.initialize(2048)
        val kp = kpg.generateKeyPair()
        val publicKey = kp.public as RSAPublicKey
        
        val n = Base64.getUrlEncoder().withoutPadding().encodeToString(publicKey.modulus.toByteArray())
        val e = Base64.getUrlEncoder().withoutPadding().encodeToString(publicKey.publicExponent.toByteArray())
        
        val jwksJson = """
        {
          "keys": [
            {
              "kid": "key-1",
              "kty": "RSA",
              "use": "sig",
              "n": "$n",
              "e": "$e"
            }
          ]
        }
        """.trimIndent()
        
        // When requesting non-existent key ID
        val provider = createTestJwksProvider(wireMockRuntimeInfo, jwksJson)
        val exception = shouldThrow<UnknownTokenException> {
            provider.getPublicKeyById("non-existent-key")
        }
        
        // Then should throw exception
        exception.message shouldContain "Public key not found for key ID"
    }
    
    @Test
    fun `should throw exception for invalid JWKS format`(wireMockRuntimeInfo: WireMockRuntimeInfo) {
        // Given invalid JWKS JSON
        val invalidJson = """{"invalid": "format"}"""
        
        // When creating provider with invalid JWKS (init catches exception and logs warning)
        val provider = createTestJwksProvider(wireMockRuntimeInfo, invalidJson)
        
        // Then trying to get a key should throw because cache is empty
        val exception = shouldThrow<UnknownTokenException> {
            provider.getPublicKeyById("any-key")
        }
        exception.message shouldContain "Public key not found for key ID"
    }
    
    @Test
    fun `should throw exception for empty JWKS keys array`(wireMockRuntimeInfo: WireMockRuntimeInfo) {
        // Given JWKS with empty keys array
        val emptyKeysJson = """{"keys": []}"""
        
        // When creating provider with empty JWKS (init catches exception and logs warning)
        val provider = createTestJwksProvider(wireMockRuntimeInfo, emptyKeysJson)
        
        // Then trying to get a key should throw because cache is empty
        val exception = shouldThrow<UnknownTokenException> {
            provider.getPublicKeyById(null)
        }
        exception.message shouldContain "No RSA public keys available in JWKS"
    }
    
    @Test
    fun `should ignore non-RSA keys in JWKS`(wireMockRuntimeInfo: WireMockRuntimeInfo) {
        // Given JWKS with mixed key types
        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.initialize(2048)
        val kp = kpg.generateKeyPair()
        val publicKey = kp.public as RSAPublicKey
        
        val n = Base64.getUrlEncoder().withoutPadding().encodeToString(publicKey.modulus.toByteArray())
        val e = Base64.getUrlEncoder().withoutPadding().encodeToString(publicKey.publicExponent.toByteArray())
        
        val jwksJson = """
        {
          "keys": [
            {
              "kid": "ec-key",
              "kty": "EC",
              "use": "sig",
              "crv": "P-256",
              "x": "base64-x",
              "y": "base64-y"
            },
            {
              "kid": "rsa-key",
              "kty": "RSA",
              "use": "sig",
              "n": "$n",
              "e": "$e"
            }
          ]
        }
        """.trimIndent()
        
        // When parsing JWKS
        val provider = createTestJwksProvider(wireMockRuntimeInfo, jwksJson)
        
        // Then should only have RSA key
        val rsaKey = provider.getPublicKeyById("rsa-key")
        rsaKey shouldNotBe null
        
        // EC key should not be available
        val exception = shouldThrow<UnknownTokenException> {
            provider.getPublicKeyById("ec-key")
        }
        exception.message shouldContain "Public key not found"
    }
    
    @Test
    fun `should return null for getPrivateKey`(wireMockRuntimeInfo: WireMockRuntimeInfo) {
        // Given any JWKS provider
        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.initialize(2048)
        val kp = kpg.generateKeyPair()
        val publicKey = kp.public as RSAPublicKey
        
        val n = Base64.getUrlEncoder().withoutPadding().encodeToString(publicKey.modulus.toByteArray())
        val e = Base64.getUrlEncoder().withoutPadding().encodeToString(publicKey.publicExponent.toByteArray())
        
        val jwksJson = """
        {
          "keys": [
            {
              "kid": "test-key",
              "kty": "RSA",
              "use": "sig",
              "n": "$n",
              "e": "$e"
            }
          ]
        }
        """.trimIndent()
        
        val provider = createTestJwksProvider(wireMockRuntimeInfo, jwksJson)
        
        // When/Then - private key operations should return null
        provider.getPrivateKey() shouldBe null
        provider.getPrivateKeyId() shouldBe null
    }
}


