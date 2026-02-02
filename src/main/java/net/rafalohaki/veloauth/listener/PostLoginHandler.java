package net.rafalohaki.veloauth.listener;

import com.velocitypowered.api.proxy.Player;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import net.rafalohaki.veloauth.cache.AuthCache;
import net.rafalohaki.veloauth.cache.AuthCache.PremiumCacheEntry;
import net.rafalohaki.veloauth.database.DatabaseManager;
import net.rafalohaki.veloauth.i18n.Messages;
import net.rafalohaki.veloauth.model.CachedAuthUser;
import net.rafalohaki.veloauth.model.RegisteredPlayer;
import org.slf4j.Logger;

import java.util.Optional;
import java.util.UUID;

/**
 * Handles post-login routing and conflict resolution logic.
 * Extracted from AuthListener to reduce complexity and improve testability.
 */
public class PostLoginHandler {

    private final AuthCache authCache;
    private final DatabaseManager databaseManager;
    private final Messages messages;
    private final Logger logger;

    /**
     * Creates a new PostLoginHandler.
     *
     * @param authCache         Cache for authorization and sessions
     * @param databaseManager   Manager for database operations
     * @param messages          i18n message system
     * @param logger            Logger instance
     */
    public PostLoginHandler(AuthCache authCache,
                           DatabaseManager databaseManager,
                           Messages messages,
                           Logger logger) {
        this.authCache = authCache;
        this.databaseManager = databaseManager;
        this.messages = messages;
        this.logger = logger;
    }

    /**
     * Handles premium player post-login (authorization and session start).
     * 
     * FIX: Check database for existing offline account with same username.
     * If found, prevent premium player from accessing to avoid nickname conflict.
     *
     * @param player   The premium player
     * @param playerIp Player's IP address
     */
    public void handlePremiumPlayer(Player player, String playerIp) {
        if (logger.isInfoEnabled()) {
            logger.info(messages.get("player.premium.verified", player.getUsername()));
        }

        UUID playerUuid = player.getUniqueId();
        
        // FIX: Check if an offline account with this username already exists
        var dbResult = databaseManager.findPlayerByNickname(player.getUsername()).join();
        if (dbResult.isDatabaseError()) {
            logger.error("Database error while checking for existing account for premium player {}: {}", 
                player.getUsername(), dbResult.getErrorMessage());
            player.disconnect(Component.text(
                messages.get("error.database.query"),
                NamedTextColor.RED
            ));
            return;
        }
        
        RegisteredPlayer existingPlayer = dbResult.getValue();
        if (existingPlayer != null) {
            // Offline account exists with this username
            UUID existingUuid = java.util.UUID.fromString(existingPlayer.getUuid());
            
            // Check if UUID matches (same player, previously registered as offline)
            if (!playerUuid.equals(existingUuid)) {
                // Different UUID - this is a nickname conflict!
                logger.warn("[PREMIUM_CONFLICT] Premium player {} (UUID: {}) conflicts with existing offline account (UUID: {})",
                    player.getUsername(), playerUuid, existingUuid);
                
                // Disconnect premium player with explanation
                player.disconnect(Component.text()
                    .append(Component.text(messages.get("auth.premium_conflict_title"), NamedTextColor.RED))
                    .append(Component.newline())
                    .append(Component.text(messages.get("auth.premium_conflict_desc"), NamedTextColor.YELLOW))
                    .append(Component.newline())
                    .append(Component.text(messages.get("auth.premium_conflict_solution"), NamedTextColor.GREEN))
                    .build());
                
                // Log audit event
                net.rafalohaki.veloauth.audit.AuditLogger.logAdminAction(
                    "SYSTEM", "PREMIUM_CONFLICT_BLOCKED", player.getUsername());
                return;
            }
            
            // Same UUID - player was previously registered as offline, now connecting as premium
            // This is OK - just update their premium status in cache
            if (logger.isInfoEnabled()) {
                logger.info("Premium player {} was previously registered as offline - allowing access", 
                    player.getUsername());
            }
        }

        UUID premiumUuid = java.util.Optional.ofNullable(authCache.getPremiumStatus(player.getUsername()))
                .map(PremiumCacheEntry::getPremiumUuid)
                .orElse(playerUuid);

        CachedAuthUser cachedUser = new CachedAuthUser(
                playerUuid,
                player.getUsername(),
                playerIp,
                System.currentTimeMillis(),
                true,
                premiumUuid);

        authCache.addAuthorizedPlayer(playerUuid, cachedUser);
        boolean sessionStarted = authCache.startSession(playerUuid, player.getUsername(), playerIp);
        
        if (!sessionStarted) {
            // Concurrent session limit reached
            player.disconnect(Component.text(
                messages.get("auth.concurrent_session_limit"),
                NamedTextColor.RED
            ));
            return;
        }

        // Premium player is now authorized in cache
        // ServerPreConnectEvent will redirect to PicoLimbo automatically
        // Then onServerConnected will trigger auto-transfer to backend
        if (logger.isDebugEnabled()) {
            logger.debug("Premium player {} authorized - ServerPreConnectEvent will route to PicoLimbo", 
                    player.getUsername());
        }
    }

    /**
     * Handles offline player post-login (authorization check or PicoLimbo transfer).
     *
     * @param player   The offline player
     * @param playerIp Player's IP address
     */
    public void handleOfflinePlayer(Player player, String playerIp) {
        if (authCache.isPlayerAuthorized(player.getUniqueId(), playerIp)) {
            if (logger.isDebugEnabled()) {
                logger.debug("\u2705 Gracz {} jest już autoryzowany - ServerPreConnectEvent przekieruje na backend",
                        player.getUsername());
            }
            return;
        }

        if (logger.isDebugEnabled()) {
            logger.debug("Gracz {} nie jest autoryzowany - ServerPreConnectEvent przekieruje na PicoLimbo", 
                    player.getUsername());
        }
        // ServerPreConnectEvent will redirect to PicoLimbo automatically
    }

    /**
     * Shows conflict resolution message to premium players in conflict mode.
     *
     * @param player The premium player experiencing conflict
     */
    public void showConflictResolutionMessage(Player player) {
        Component message = Component.text()
                .append(Component.text(messages.get("player.conflict.header"), NamedTextColor.YELLOW))
                .append(Component.newline())
                .append(Component.text(messages.get("player.conflict.description"), NamedTextColor.RED))
                .append(Component.newline())
                .append(Component.text(messages.get("player.conflict.options"), NamedTextColor.WHITE))
                .append(Component.newline())
                .append(Component.text(messages.get("player.conflict.option1"), NamedTextColor.GRAY))
                .append(Component.newline())
                .append(Component.text(messages.get("player.conflict.option2"), NamedTextColor.GREEN))
                .append(Component.newline())
                .append(Component.text(messages.get("player.conflict.resolution"), NamedTextColor.AQUA))
                .build();

        player.sendMessage(message);
        logger.info("[CONFLICT MESSAGE] Sent conflict resolution message to premium player: {}", player.getUsername());
    }

    /**
     * Checks if player should see conflict resolution message.
     *
     * @param player The player to check
     * @return true if player is in conflict mode and is premium
     */
    public boolean shouldShowConflictMessage(Player player) {
        RegisteredPlayer registeredPlayer = databaseManager.findPlayerWithRuntimeDetection(player.getUsername())
                .join().getValue();
        
        if (registeredPlayer == null || !registeredPlayer.getConflictMode()) {
            return false;
        }

        return Optional.ofNullable(authCache.getPremiumStatus(player.getUsername()))
                .map(PremiumCacheEntry::isPremium)
                .orElse(false);
    }
}
