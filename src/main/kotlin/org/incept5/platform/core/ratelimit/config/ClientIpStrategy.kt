package org.incept5.platform.core.ratelimit.config

/**
 * Strategy used by [org.incept5.platform.core.ratelimit.ip.ClientIpResolver] to derive the
 * client IP that a rate-limit bucket is keyed on.
 *
 * The default — [TRUSTED_PROXY_HOPS] — is spoof-resistant: trusted proxies (ALB, Kong) append
 * the address they observed to the *right* of `X-Forwarded-For`, so counting a fixed number of
 * hops from the right yields the genuine client IP regardless of how many spoofed values a
 * caller injects on the left. The previously-used leftmost-XFF behaviour ([LEFTMOST_XFF]) is
 * retained only as an explicit, opt-in escape hatch — it is no longer the default.
 */
enum class ClientIpStrategy {
    /**
     * Take the Nth-from-right value of `X-Forwarded-For`, where N is
     * `rate-limit.client-ip.trusted-proxy-hops`. This is the safe default for deployments
     * behind a known chain of trusted proxies (e.g. ALB + Kong = 2 hops).
     */
    TRUSTED_PROXY_HOPS,

    /** Use the `X-Real-IP` header (falling back to the remote address when absent). */
    X_REAL_IP,

    /** Use the TCP remote address only; ignore forwarding headers entirely. */
    REMOTE_ADDR,

    /**
     * Legacy: take the leftmost value of `X-Forwarded-For`. Spoofable — provided only for
     * backwards compatibility / local testing. Do not use in front of an untrusted edge.
     */
    LEFTMOST_XFF,
}
