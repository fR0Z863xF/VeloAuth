package net.rafalohaki.veloauth.audit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import java.net.InetAddress;
import java.time.Instant;
import java.util.UUID;

/**
 * Centralized audit logging for security-critical events.
 * All authentication, authorization, and security events are logged here.
 * 
 * <p>Audit logs include:
 * <ul>
 *   <li>Login attempts (success/failure)</li>
 *   <li>Registration events</li>
 *   <li>Password changes</li>
 *   <li>Session events (start/end/hijack)</li>
 *   <li>Rate limiting events</li>
 *   <li>Premium status changes</li>
 *   <li>Administrative actions</li>
 * </ul>
 * 
 * @since 1.0.4
 */
public class AuditLogger {

    private static final Logger logger = LoggerFactory.getLogger(AuditLogger.class);
    private static final Marker AUDIT_MARKER = MarkerFactory.getMarker("AUDIT");
    private static final Marker SECURITY_MARKER = MarkerFactory.getMarker("SECURITY");

    /**
     * Logs a successful login attempt.
     */
    public static void logLoginSuccess(String username, UUID playerUuid, String ip) {
        logger.info(AUDIT_MARKER, "[LOGIN_SUCCESS] User: {}, UUID: {}, IP: {}, Time: {}", 
                   username, playerUuid, ip, Instant.now());
    }

    /**
     * Logs a failed login attempt.
     */
    public static void logLoginFailure(String username, String ip, String reason) {
        logger.warn(AUDIT_MARKER, "[LOGIN_FAILURE] User: {}, IP: {}, Reason: {}, Time: {}", 
                   username, ip, reason, Instant.now());
    }

    /**
     * Logs a successful registration.
     */
    public static void logRegistration(String username, UUID playerUuid, String ip) {
        logger.info(AUDIT_MARKER, "[REGISTRATION] User: {}, UUID: {}, IP: {}, Time: {}", 
                   username, playerUuid, ip, Instant.now());
    }

    /**
     * Logs a password change.
     */
    public static void logPasswordChange(String username, UUID playerUuid, String ip) {
        logger.info(AUDIT_MARKER, "[PASSWORD_CHANGE] User: {}, UUID: {}, IP: {}, Time: {}", 
                   username, playerUuid, ip, Instant.now());
    }

    /**
     * Logs session start.
     */
    public static void logSessionStart(String username, UUID playerUuid, String ip) {
        logger.info(AUDIT_MARKER, "[SESSION_START] User: {}, UUID: {}, IP: {}, Time: {}", 
                   username, playerUuid, ip, Instant.now());
    }

    /**
     * Logs session end.
     */
    public static void logSessionEnd(String username, UUID playerUuid, String reason) {
        logger.info(AUDIT_MARKER, "[SESSION_END] User: {}, UUID: {}, Reason: {}, Time: {}", 
                   username, playerUuid, reason, Instant.now());
    }

    /**
     * Logs session hijacking attempt.
     */
    public static void logSessionHijackAttempt(UUID playerUuid, String expectedIp, String actualIp) {
        logger.warn(SECURITY_MARKER, "[SESSION_HIJACK] UUID: {}, Expected IP: {}, Actual IP: {}, Time: {}", 
                   playerUuid, expectedIp, actualIp, Instant.now());
    }

    /**
     * Logs rate limiting event.
     */
    public static void logRateLimitTriggered(String ip, String eventType) {
        logger.warn(SECURITY_MARKER, "[RATE_LIMIT] IP: {}, Event: {}, Time: {}", 
                   ip, eventType, Instant.now());
    }

    /**
     * Logs brute force block.
     */
    public static void logBruteForceBlock(String username, String ip, int attempts) {
        logger.warn(SECURITY_MARKER, "[BRUTE_FORCE_BLOCK] User: {}, IP: {}, Attempts: {}, Time: {}", 
                   username, ip, attempts, Instant.now());
    }

    /**
     * Logs concurrent session limit reached.
     */
    public static void logConcurrentSessionLimit(String username, int currentSessions, int maxSessions) {
        logger.warn(SECURITY_MARKER, "[CONCURRENT_SESSION_LIMIT] User: {}, Current: {}, Max: {}, Time: {}", 
                   username, currentSessions, maxSessions, Instant.now());
    }

    /**
     * Logs administrative action.
     */
    public static void logAdminAction(String adminName, String action, String target) {
        logger.info(AUDIT_MARKER, "[ADMIN_ACTION] Admin: {}, Action: {}, Target: {}, Time: {}", 
                   adminName, action, target, Instant.now());
    }

    /**
     * Logs account deletion.
     */
    public static void logAccountDeletion(String username, String deletedBy) {
        logger.info(AUDIT_MARKER, "[ACCOUNT_DELETION] User: {}, Deleted by: {}, Time: {}", 
                   username, deletedBy, Instant.now());
    }

    /**
     * Logs premium status change.
     */
    public static void logPremiumStatusChange(String username, boolean isPremium) {
        logger.info(AUDIT_MARKER, "[PREMIUM_STATUS] User: {}, Premium: {}, Time: {}", 
                   username, isPremium, Instant.now());
    }

    /**
     * Logs PreLogin rate limit block.
     */
    public static void logPreLoginRateLimit(String username, InetAddress address) {
        logger.warn(SECURITY_MARKER, "[PRELOGIN_RATE_LIMIT] User: {}, IP: {}, Time: {}", 
                   username, address != null ? address.getHostAddress() : "unknown", Instant.now());
    }

    /**
     * Logs all sessions invalidated (e.g., after password change).
     */
    public static void logAllSessionsInvalidated(String username, String reason) {
        logger.info(AUDIT_MARKER, "[ALL_SESSIONS_INVALIDATED] User: {}, Reason: {}, Time: {}", 
                   username, reason, Instant.now());
    }
}
