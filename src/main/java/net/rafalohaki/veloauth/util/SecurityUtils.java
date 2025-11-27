package net.rafalohaki.veloauth.util;

import net.rafalohaki.veloauth.cache.AuthCache;
import net.rafalohaki.veloauth.command.IPRateLimiter;

import java.net.InetAddress;

/**
 * Utility class for common security operations.
 * Provides reusable methods for security counter management and brute force protection.
 * <p>
 * Thread-safe: delegates to thread-safe components (AuthCache, IPRateLimiter).
 */
public final class SecurityUtils {

    private SecurityUtils() {
        // Utility class - prevent instantiation
    }

    /**
     * Resets all security counters for a given IP address.
     * This includes login attempt counters and rate limiting.
     * <p>
     * Typically called after successful authentication to clear any failed attempt history.
     *
     * @param address     IP address to reset counters for (null-safe)
     * @param authCache   AuthCache instance for login attempt tracking
     * @param rateLimiter IPRateLimiter instance for rate limiting
     */
    public static void resetSecurityCounters(InetAddress address, AuthCache authCache, 
                                            IPRateLimiter rateLimiter) {
        if (address != null) {
            authCache.resetLoginAttempts(address);
            rateLimiter.reset(address);
        }
    }

    /**
     * Checks if an IP address is blocked due to brute force attempts.
     *
     * @param address   IP address to check (null-safe)
     * @param authCache AuthCache instance for brute force tracking
     * @return true if blocked, false otherwise
     */
    public static boolean isBruteForceBlocked(InetAddress address, AuthCache authCache) {
        return address != null && authCache.isBlocked(address);
    }

    /**
     * Registers a failed login attempt and returns whether the IP is now blocked.
     *
     * @param address   IP address that failed login (null-safe)
     * @param authCache AuthCache instance for brute force tracking
     * @return true if IP is now blocked, false otherwise
     */
    public static boolean registerFailedLogin(InetAddress address, AuthCache authCache) {
        return address != null && authCache.registerFailedLogin(address);
    }
}
