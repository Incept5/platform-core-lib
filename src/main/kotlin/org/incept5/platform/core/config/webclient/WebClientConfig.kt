package org.incept5.platform.core.config.webclient

import jakarta.enterprise.context.ApplicationScoped
import jakarta.enterprise.inject.Produces
import org.jboss.logging.Logger
import org.springframework.web.reactive.function.client.ExchangeFilterFunction
import org.springframework.web.reactive.function.client.WebClient
import reactor.core.publisher.Mono
import kotlin.collections.forEach
import kotlin.collections.joinToString
import kotlin.jvm.java

@ApplicationScoped
class WebClientConfig {
    private val log = Logger.getLogger(WebClientConfig::class.java)

    private fun logRequest(): ExchangeFilterFunction {
        return ExchangeFilterFunction.ofRequestProcessor { clientRequest ->
            if (log.isDebugEnabled) {
                val headers = clientRequest.headers().entries.joinToString(", ") { "${it.key}=${it.value}" }
                log.debug("Request: ${clientRequest.method()} ${clientRequest.url()}")
                log.debug("Headers: $headers")
            }
            Mono.just(clientRequest)
        }
    }

    private fun logResponse(): ExchangeFilterFunction {
        return ExchangeFilterFunction.ofResponseProcessor { clientResponse ->
            if (log.isDebugEnabled) {
                log.debug("Response Status: ${clientResponse.statusCode()}")
                clientResponse.headers().asHttpHeaders().forEach { name, values ->
                    values.forEach { value ->
                        log.debug("Response Header: $name=$value")
                    }
                }
            }
            Mono.just(clientResponse)
        }
    }

    @Produces
    @ApplicationScoped
    fun webClient(): WebClient {
        return WebClient.builder()
            .filter(logRequest())
            .filter(logResponse())
            .build()
    }
}
