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

    private fun generateRsaKeyPair(): RSAPublicKey {
        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.initialize(2048)
        return kpg.generateKeyPair().public as RSAPublicKey
    }

    private fun modulus(key: RSAPublicKey): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(key.modulus.toByteArray())

    private fun exponent(key: RSAPublicKey): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(key.publicExponent.toByteArray())

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
    fun `should parse a key set whose keys carry an x5c certificate chain`(wireMockRuntimeInfo: WireMockRuntimeInfo) {
        // Given a Keycloak-shaped JWKS: the signing key publishes its X.509 chain as a nested
        // array, and an RSA-OAEP encryption key sits alongside it. The nested `]` closing `x5c`
        // is what the old regex parser mistook for the end of the key set — it read a truncated
        // fragment of the first key and reported "No valid RSA keys found in JWKS".
        val sig = generateRsaKeyPair()
        val enc = generateRsaKeyPair()

        val jwksJson = """
        {
          "keys": [
            {
              "kid": "sig-key",
              "kty": "RSA",
              "alg": "RS256",
              "use": "sig",
              "n": "${modulus(sig)}",
              "e": "${exponent(sig)}",
              "x5c": [ "MIICmzCCAYMCBgGY", "MIIDdzCCAl+gAwIB" ],
              "x5t": "abc123",
              "x5t#S256": "def456"
            },
            {
              "kid": "enc-key",
              "kty": "RSA",
              "alg": "RSA-OAEP",
              "use": "enc",
              "n": "${modulus(enc)}",
              "e": "${exponent(enc)}",
              "x5c": [ "MIICmzCCAYMCBgGY" ]
            }
          ]
        }
        """.trimIndent()

        // When parsing the JWKS
        val provider = createTestJwksProvider(wireMockRuntimeInfo, jwksJson)

        // Then the signing key — the second key in document order after the nested array — is
        // cached with its true modulus
        val retrieved = provider.getPublicKeyById("sig-key")
        retrieved.modulus shouldBe sig.modulus
        retrieved.publicExponent shouldBe sig.publicExponent

        // And the encryption key is not: it cannot verify an RS256 signature
        val exception = shouldThrow<UnknownTokenException> { provider.getPublicKeyById("enc-key") }
        exception.message shouldContain "Public key not found"
    }

    @Test
    fun `should cache a key that omits the optional use field`(wireMockRuntimeInfo: WireMockRuntimeInfo) {
        // Given a JWKS whose key has no "use" — RFC 7517 makes the field optional, and an IdP
        // that omits it must not be treated as publishing no signing keys
        val kp = generateRsaKeyPair()
        val jwksJson = """
        {"keys":[{"kid":"no-use","kty":"RSA","n":"${modulus(kp)}","e":"${exponent(kp)}"}]}
        """.trimIndent()

        // When parsing the JWKS
        val provider = createTestJwksProvider(wireMockRuntimeInfo, jwksJson)

        // Then the key is usable
        provider.getPublicKeyById("no-use").modulus shouldBe kp.modulus
    }

    @Test
    fun `should keep the rest of the key set when one key is undecodable`(wireMockRuntimeInfo: WireMockRuntimeInfo) {
        // Given a JWKS carrying one key whose modulus is not valid base64url
        val good = generateRsaKeyPair()
        val jwksJson = """
        {
          "keys": [
            {"kid":"broken","kty":"RSA","use":"sig","n":"!!!not base64!!!","e":"AQAB"},
            {"kid":"good","kty":"RSA","use":"sig","n":"${modulus(good)}","e":"${exponent(good)}"}
          ]
        }
        """.trimIndent()

        // When parsing the JWKS
        val provider = createTestJwksProvider(wireMockRuntimeInfo, jwksJson)

        // Then the usable key is still cached
        provider.getPublicKeyById("good").modulus shouldBe good.modulus
    }

    @Test
    fun `should skip a key whose members are JSON null rather than caching a nonsense key`(
        wireMockRuntimeInfo: WireMockRuntimeInfo
    ) {
        // Given a JWKS whose first key has a null modulus. Read as text that is the string
        // "null" — four valid base64url characters — so it must be rejected as a non-string,
        // not decoded into a 3-byte modulus and cached under "null-n".
        val good = generateRsaKeyPair()
        val jwksJson = """
        {
          "keys": [
            {"kid":"null-n","kty":"RSA","use":"sig","n":null,"e":"AQAB"},
            {"kid":"good","kty":"RSA","use":"sig","n":"${modulus(good)}","e":"${exponent(good)}"}
          ]
        }
        """.trimIndent()

        // When parsing the JWKS
        val provider = createTestJwksProvider(wireMockRuntimeInfo, jwksJson)

        // Then only the real key is cached
        provider.getPublicKeyById("good").modulus shouldBe good.modulus
        val exception = shouldThrow<UnknownTokenException> { provider.getPublicKeyById("null-n") }
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


