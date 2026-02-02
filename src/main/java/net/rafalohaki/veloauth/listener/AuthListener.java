package net.rafalohaki.veloauth.listener;

import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.connection.DisconnectEvent;
import com.velocitypowered.api.event.connection.LoginEvent;
import com.velocitypowered.api.event.connection.PostLoginEvent;
import com.velocitypowered.api.event.connection.PreLoginEvent;
import com.velocitypowered.api.event.player.ServerConnectedEvent;
import com.velocitypowered.api.event.player.ServerPreConnectEvent;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.server.RegisteredServer;
import static com.velocitypowered.api.event.ResultedEvent.ComponentResult;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import net.rafalohaki.veloauth.VeloAuth;
import net.rafalohaki.veloauth.cache.AuthCache;
import net.rafalohaki.veloauth.config.Settings;
import net.rafalohaki.veloauth.connection.ConnectionManager;
import net.rafalohaki.veloauth.database.DatabaseManager;
import net.rafalohaki.veloauth.database.DatabaseManager.DbResult;
import net.rafalohaki.veloauth.model.RegisteredPlayer;
import net.rafalohaki.veloauth.i18n.Messages;
import net.rafalohaki.veloauth.util.PlayerAddressUtils;
import org.slf4j.Logger;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import javax.inject.Inject;
import java.net.InetAddress;
import java.util.Optional;
import java.util.UUID;

/**
 * Listener eventów autoryzacji VeloAuth.
 * Obsługuje połączenia graczy i kieruje ich na odpowiednie serwery.
 * 
 * <p><b>Flow eventów:</b>
 * <ol>
 *   <li>PreLoginEvent → sprawdź premium i force online mode</li>
 *   <li>LoginEvent → sprawdź brute force</li>
 *   <li>PostLoginEvent → kieruj na PicoLimbo lub backend</li>
 *   <li>ServerPreConnectEvent → blokuj nieautoryzowane połączenia z backend</li>
 *   <li>ServerConnectedEvent → loguj transfery</li>
 * </ol>
 * 
 * <p><b>Initialization Safety (v2.0.0):</b>
 * Handlers (PreLoginHandler, PostLoginHandler) are now initialized before AuthListener
 * construction and passed via constructor, preventing NullPointerException during event
 * processing. Defense-in-depth null checks are included in event handlers as additional safety.
 * 
 * <p><b>Thread Safety:</b> All event handlers are thread-safe and can process concurrent events.
 * 
 * @since 1.0.0
 * @see PreLoginHandler
 * @see PostLoginHandler
 */
public class AuthListener {

    // Markery SLF4J dla kategoryzowanego logowania
    private static final Marker AUTH_MARKER = MarkerFactory.getMarker("AUTH");
    private static final Marker SECURITY_MARKER = MarkerFactory.getMarker("SECURITY");

    private final VeloAuth plugin;
    private final AuthCache authCache;
    private final Settings settings;
    private final Logger logger;
    private final Messages messages;
    private final DatabaseManager databaseManager;
    
    // Handler instances for delegating complex logic
    private final PreLoginHandler preLoginHandler;
    private final PostLoginHandler postLoginHandler;
    private final ConnectionManager connectionManager;
    private final UuidVerificationHandler uuidVerificationHandler;
    
    // PreLogin rate limiter to prevent DoS attacks
    private final net.rafalohaki.veloauth.command.IPRateLimiter preLoginRateLimiter;

    /**
     * Tworzy nowy AuthListener.
     *
     * @param plugin            VeloAuth plugin instance
     * @param authCache         Cache autoryzacji
     * @param settings          Ustawienia pluginu
     * @param preLoginHandler   Handler for pre-login logic
     * @param postLoginHandler  Handler for post-login logic
     * @param connectionManager Manager połączeń i transferów
     * @param databaseManager   Manager bazy danych
     * @param messages          System wiadomości i18n
     */
    @Inject
    public AuthListener(VeloAuth plugin,
            AuthCache authCache,
            Settings settings,
            PreLoginHandler preLoginHandler,
            PostLoginHandler postLoginHandler,
            ConnectionManager connectionManager,
            DatabaseManager databaseManager,
            Messages messages) {
        this.plugin = plugin;
        this.authCache = authCache;
        this.settings = settings;
        this.logger = plugin.getLogger();
        this.databaseManager = databaseManager;
        this.messages = messages;
        this.connectionManager = java.util.Objects.requireNonNull(connectionManager, 
            "ConnectionManager cannot be null - initialization failed");
        this.preLoginHandler = java.util.Objects.requireNonNull(preLoginHandler, 
            "PreLoginHandler cannot be null - initialization failed");
        this.postLoginHandler = java.util.Objects.requireNonNull(postLoginHandler, 
            "PostLoginHandler cannot be null - initialization failed");
        this.uuidVerificationHandler = new UuidVerificationHandler(databaseManager, authCache, logger);
        
        // Initialize PreLogin rate limiter
        this.preLoginRateLimiter = new net.rafalohaki.veloauth.command.IPRateLimiter(
            settings.getPreLoginRateLimitAttempts(), 
            settings.getPreLoginRateLimitMinutes()
        );

        if (logger.isDebugEnabled()) {
            logger.debug(messages.get("connection.listener.registered"));
        }
    }

    /**
     * Resolves the block reason for unauthorized connections.
     *
     * @param isAuthorized     Whether player is authorized
     * @param hasActiveSession Whether player has active session
     * @return Human-readable reason string (English for logs)
     */
    private static String resolveBlockReason(boolean isAuthorized, boolean hasActiveSession) {
        if (!isAuthorized) {
            return "unauthorized";
        }
        if (!hasActiveSession) {
            return "no active session";
        }
        return "UUID mismatch";
    }



    /**
     * ✅ KLUCZOWY EVENT - PreLoginEvent
     * Tutaj sprawdzamy premium PRZED weryfikacją UUID!
     * Jeśli premium → forceOnlineMode() = Velocity zweryfikuje
     * <p>
     * KRYTYCZNE: Używamy async = false + maksymalny priorytet dla bezpieczeństwa
     * Zapobiega race conditions gdzie async handlers mogą wykonać się przed sync
     * handlers
     * <p>
     * UWAGA: PreLoginEvent WYMAGA synchronicznej odpowiedzi.
     * Premium resolution na cache miss blokuje, ale to ograniczenie API Velocity.
     * Dwa warstwy cache (AuthCache + PremiumResolverService) minimalizują impact.
     * <p>
     * FIX: Added PreLogin rate limiting to prevent DoS attacks (Issue #2)
     */
    @Subscribe(priority = Short.MAX_VALUE)
    public void onPreLogin(PreLoginEvent event) {
        String username = event.getUsername();
        if (logger.isDebugEnabled()) {
            logger.debug("\uD83D\uDD0D PreLogin: {}", username);
        }

        // FIX: Check PreLogin rate limit FIRST to prevent DoS
        InetAddress address = event.getConnection().getRemoteAddress().getAddress();
        if (preLoginRateLimiter.isRateLimited(address)) {
            logger.warn(SECURITY_MARKER, 
                "[PRELOGIN_RATE_LIMIT] IP {} exceeded PreLogin rate limit for user {}", 
                address.getHostAddress(), username);
            
            // Log audit event
            net.rafalohaki.veloauth.audit.AuditLogger.logPreLoginRateLimit(username, address);
            
            event.setResult(PreLoginEvent.PreLoginComponentResult.denied(
                Component.text(messages.get("auth.rate_limit_prelogin"), NamedTextColor.RED)
            ));
            return;
        }
        
        // Increment rate limit counter
        preLoginRateLimiter.incrementAttempts(address);

        if (!validatePreLoginConditions(event, username)) {
            return;
        }

        if (!settings.isPremiumCheckEnabled()) {
            logger.debug("Premium check wyłączony w konfiguracji - wymuszam offline mode dla {}", username);
            event.setResult(PreLoginEvent.PreLoginComponentResult.forceOfflineMode());
            return;
        }

        handlePremiumDetection(event, username);
    }

    private boolean validatePreLoginConditions(PreLoginEvent event, String username) {
        if (!validatePluginInitialized(event, username)) {
            return false;
        }
        if (!validateHandlerInitialized(event, username)) {
            return false;
        }
        if (!validateUsername(event, username)) {
            return false;
        }
        return !checkBruteForceBlocked(event);
    }

    private boolean validatePluginInitialized(PreLoginEvent event, String username) {
        if (!plugin.isInitialized()) {
            logger.warn("🔒 STARTUP BLOCK: Player {} tried to connect before VeloAuth fully initialized - PreLogin block", username);
            String msg = messages != null ? messages.get("system.starting") : "VeloAuth is starting. Please wait.";
            event.setResult(PreLoginEvent.PreLoginComponentResult.denied(Component.text(msg, NamedTextColor.RED)));
            return false;
        }
        return true;
    }

    private boolean validateHandlerInitialized(PreLoginEvent event, String username) {
        if (preLoginHandler == null) {
            logger.error("CRITICAL: PreLoginHandler is null during event processing for player {}", username);
            String msg = messages != null ? messages.get("system.init_error") : "System initialization error.";
            event.setResult(PreLoginEvent.PreLoginComponentResult.denied(Component.text(msg, NamedTextColor.RED)));
            return false;
        }
        return true;
    }

    private boolean validateUsername(PreLoginEvent event, String username) {
        if (!preLoginHandler.isValidUsername(username)) {
            logger.warn(SECURITY_MARKER, "[USERNAME VALIDATION FAILED] {} - invalid format", username);
            event.setResult(PreLoginEvent.PreLoginComponentResult.denied(
                    Component.text(messages.get("validation.username.invalid"), NamedTextColor.RED)));
            return false;
        }
        return true;
    }

    private boolean checkBruteForceBlocked(PreLoginEvent event) {
        InetAddress playerAddress = PlayerAddressUtils.getAddressFromPreLogin(event);
        if (playerAddress != null && preLoginHandler.isBruteForceBlocked(playerAddress)) {
            if (logger.isWarnEnabled()) {
                logger.warn(SECURITY_MARKER, "[BRUTE FORCE BLOCK] IP {} blocked", playerAddress.getHostAddress());
            }
            event.setResult(PreLoginEvent.PreLoginComponentResult.denied(
                    Component.text(messages.get("security.brute_force.blocked"), NamedTextColor.RED)));
            return true;
        }
        return false;
    }

    private void handlePremiumDetection(PreLoginEvent event, String username) {
        // Delegate premium resolution to PreLoginHandler
        PreLoginHandler.PremiumResolutionResult result = preLoginHandler.resolvePremiumStatus(username);
        boolean premium = result.premium();

        // 🔥 USE_OFFLINE: Check for nickname conflicts with runtime detection
        RegisteredPlayer existingPlayer = databaseManager.findPlayerWithRuntimeDetection(username).join().getValue();

        if (existingPlayer != null) {
            boolean existingIsPremium = databaseManager.isPlayerPremiumRuntime(existingPlayer);

            if (preLoginHandler.isNicknameConflict(existingPlayer, premium, existingIsPremium)) {
                preLoginHandler.handleNicknameConflict(event, existingPlayer, premium);
                return;
            }
        }

        // FIX: 离线玩家尝试使用正版昵称 - 显示友好提示而不是"无效的会话"
        if (!premium && result.premiumUuid() == null) {
            // Check if this nickname is actually a premium account
            PreLoginHandler.PremiumResolutionResult actualPremiumCheck = preLoginHandler.resolvePremiumStatus(username);
            if (actualPremiumCheck.premium() && actualPremiumCheck.premiumUuid() != null) {
                // This is a premium nickname, but player is connecting in offline mode
                logger.warn(SECURITY_MARKER, 
                    "[OFFLINE_PREMIUM_CONFLICT] Offline player trying to use premium nickname: {}", username);
                
                event.setResult(PreLoginEvent.PreLoginComponentResult.denied(
                    Component.text(messages.get("auth.offline_premium_conflict"), NamedTextColor.YELLOW)
                ));
                return;
            }
        }

        if (premium) {
            event.setResult(PreLoginEvent.PreLoginComponentResult.forceOnlineMode());
        } else {
            event.setResult(PreLoginEvent.PreLoginComponentResult.forceOfflineMode());
        }
    }



    /**
     * Obsługuje event logowania gracza.
     * Sprawdza brute force i premium status SYNCHRONICZNIE.
     * <p>
     * KRYTYCZNE: Używamy async = false + maksymalny priorytet dla bezpieczeństwa
     * Zapobiega race conditions w procesie autoryzacji
     */
    @Subscribe(priority = Short.MAX_VALUE)
    public void onLogin(LoginEvent event) {
        Player player = event.getPlayer();
        String playerName = player.getUsername();
        UUID playerUuid = player.getUniqueId();
        String playerIp = PlayerAddressUtils.getPlayerIp(player);

        boolean allowed = true;
        try {
            // CRITICAL SECURITY: Block login attempts until plugin is fully initialized
            if (!plugin.isInitialized()) {
                logger.warn(
                        "🔒 STARTUP BLOCK: Player {} tried to login before VeloAuth fully initialized - login block",
                        playerName);
                // Use English fallback - Messages not available yet
                event.setResult(ComponentResult.denied(
                        Component.text(messages.get("system.starting"),
                                NamedTextColor.RED)));
                return;
            }

            logger.debug("LoginEvent dla gracza {} (UUID: {}) z IP {}",
                    playerName, playerUuid, playerIp);

            // 1. Check brute force block
            InetAddress playerAddress = PlayerAddressUtils.getPlayerAddress(player);
            if (playerAddress != null && authCache.isBlocked(playerAddress)) {
                logger.warn(SECURITY_MARKER, "Blocked connection for player {} - too many failed login attempts",
                        playerName);

                event.setResult(ComponentResult.denied(
                        Component.text(messages.get("security.brute_force.blocked"), NamedTextColor.RED)));
                return;
            }

            // Premium check został przeniesiony do PreLoginEvent

        } catch (Exception e) {
            logger.error("Error handling LoginEvent for player: {}", event.getPlayer().getUsername(), e);

            event.setResult(ComponentResult.denied(
                    Component.text(messages.get("connection.error.generic"), NamedTextColor.RED)));
            allowed = false;
        }

        if (allowed) {
            event.setResult(ComponentResult.allowed());
        }
    }

    /**
     * Obsługuje disconnect gracza - kończy sesję premium.
     * Zapobiega session hijacking przez natychmiastowe kończenie sesji.
     */
    @Subscribe(priority = 0) // NORMAL priority
    public void onDisconnect(DisconnectEvent event) {
        try {
            Player player = event.getPlayer();

            // ✅ SESJE TRWAŁE: Nie kończ sesji przy rozłączeniu
            // Sesje powinny być trwałe dla autoryzowanych graczy offline
            // Kończymy tylko przy /logout, timeout lub banie
            
            // Cleanup retry attempts counter to prevent memory leak
            connectionManager.clearRetryAttempts(player.getUniqueId());

            if (logger.isDebugEnabled()) {
                logger.debug("Gracz {} rozłączył się - sesja pozostaje aktywna", player.getUsername());
            }

        } catch (Exception e) {
            logger.error("Błąd podczas obsługi DisconnectEvent dla gracza: {}", event.getPlayer().getUsername(), e);
        }
    }

    /**
     * Obsługuje event po zalogowaniu gracza.
     * Kieruje gracza na odpowiedni serwer (PicoLimbo lub backend).
     */
    @Subscribe(priority = 0) // NORMAL priority
    public void onPostLogin(PostLoginEvent event) {
        Player player = event.getPlayer();
        String playerIp = PlayerAddressUtils.getPlayerIp(player);

        logger.debug("PostLoginEvent dla gracza {} z IP {}",
                player.getUsername(), playerIp);

        // DEFENSE-IN-DEPTH: Verify handlers are initialized
        if (postLoginHandler == null) {
            logger.error("CRITICAL: PostLoginHandler is null during event processing for player {}", 
                player.getUsername());
            String msg = messages != null ? messages.get("system.init_error") : "System initialization error.";
            player.disconnect(Component.text(msg, NamedTextColor.RED));
            return;
        }

        try {
            // 🔥 USE_OFFLINE: Check for conflict resolution messages - delegate to PostLoginHandler
            // ASYNC: Run in separate task to avoid blocking event loop with DB operations
            plugin.getServer().getScheduler().buildTask(plugin, () -> {
                try {
                    if (postLoginHandler.shouldShowConflictMessage(player)) {
                        postLoginHandler.showConflictResolutionMessage(player);
                    }
                } catch (Exception e) {
                    logger.error("Error checking conflict message for {}", player.getUsername(), e);
                }
            }).schedule();

            // Delegate to PostLoginHandler based on player mode
            if (player.isOnlineMode()) {
                postLoginHandler.handlePremiumPlayer(player, playerIp);
                return;
            }

            // Handle offline player - delegate to PostLoginHandler
            postLoginHandler.handleOfflinePlayer(player, playerIp);

        } catch (Exception e) {
            logger.error("Error handling PostLoginEvent for player: {}", event.getPlayer().getUsername(), e);

            event.getPlayer().disconnect(Component.text(
                    messages.get("connection.error.generic"),
                    NamedTextColor.RED));
        }
    }

    /**
     * Obsługuje event przed połączeniem z serwerem.
     * Blokuje nieautoryzowane połączenia z serwerami backend.
     * <p>
     * KRYTYCZNE: Używamy async = false + maksymalny priorytet dla bezpieczeństwa
     * Zapobiega obejściu autoryzacji przez race conditions
     * <p>
     * FLOW dla nowych graczy (pierwszego połączenia):
     * - Velocity próbuje połączyć z pierwszym serwerem z listy try (np. 2b2t)
     * - My przechwytujemy i przekierowujemy na PicoLimbo
     * - Po połączeniu z PicoLimbo, onServerConnected uruchomi auto-transfer
     */
    @Subscribe(priority = Short.MAX_VALUE)
    public void onServerPreConnect(ServerPreConnectEvent event) {
        try {
            Player player = event.getPlayer();
            // NAPRAWIONE: Używamy getOriginalServer() zamiast getTarget()
            // getOriginalServer() to INPUT field (dokąd gracz chce iść)
            String targetServerName = event.getOriginalServer().getServerInfo().getName();

            logger.debug("ServerPreConnectEvent dla gracza {} -> serwer {}",
                    player.getUsername(), targetServerName);

            if (handleFirstConnection(event, player, targetServerName)) {
                return;
            }

            // ✅ JEŚLI TO PICOLIMBO - SPRAWDŹ DODATKOWO AUTORYZACJĘ
            if (handlePicoLimboConnection(event, player, targetServerName)) {
                return;
            }

            // ✅ JEŚLI TO BACKEND - SPRAWDŹ AUTORYZACJĘ + SESJĘ + CACHE
            verifyBackendConnection(event, player, targetServerName);

        } catch (Exception e) {
            logger.error("Błąd w ServerPreConnect", e);
            event.setResult(ServerPreConnectEvent.ServerResult.denied());
        }
    }

    private boolean handleFirstConnection(ServerPreConnectEvent event, Player player, String targetServerName) {
        // ✅ PIERWSZE POŁĄCZENIE: Gracz nie ma jeszcze currentServer
        // Velocity próbuje go wysłać na pierwszy serwer z try (np. 2b2t)
        // My MUSIMY przekierować na PicoLimbo dla ViaVersion compatibility
        if (player.getCurrentServer().isEmpty()) {
            String picoLimboName = settings.getPicoLimboServerName();
            
            // Jeśli cel to już PicoLimbo - pozwól
            if (targetServerName.equals(picoLimboName)) {
                logger.debug("Pierwsze połączenie {} -> PicoLimbo - pozwalam", player.getUsername());
                return true;
            }
            
            // Przekieruj na PicoLimbo zamiast backend
            Optional<RegisteredServer> picoLimbo = plugin.getServer().getServer(picoLimboName);
            if (picoLimbo.isPresent()) {
                logger.debug("Pierwsze połączenie {} -> {} - przekierowuję na PicoLimbo", 
                        player.getUsername(), targetServerName);
                event.setResult(ServerPreConnectEvent.ServerResult.allowed(picoLimbo.get()));
            } else {
                logger.error("PicoLimbo server '{}' nie znaleziony! Gracz {} nie może się połączyć.", 
                        picoLimboName, player.getUsername());
                event.setResult(ServerPreConnectEvent.ServerResult.denied());
            }
            return true;
        }
        return false;
    }

    private boolean handlePicoLimboConnection(ServerPreConnectEvent event, Player player, String targetServerName) {
        if (targetServerName.equals(settings.getPicoLimboServerName())) {
            // DODATKOWA WERYFIKACJA - sprawdź czy gracz nie jest już autoryzowany
            // Jeśli jest autoryzowany, nie powinien iść na PicoLimbo
            String playerIp = PlayerAddressUtils.getPlayerIp(player);
            boolean isAuthorized = authCache.isPlayerAuthorized(player.getUniqueId(), playerIp);
            if (isAuthorized) {
                // AUTORYZOWANY GRACZ NA PICOLIMBO - przekieruj na backend
                logger.debug("Autoryzowany gracz {} próbuje iść na PicoLimbo - przekierowuję na backend",
                        player.getUsername());
                event.setResult(ServerPreConnectEvent.ServerResult.denied());
                // Velocity automatycznie przekieruje na inny serwer
            } else {
                logger.debug("PicoLimbo - pozwól (gracz nie jest autoryzowany)");
            }
            return true;
        }
        return false;
    }

    private void verifyBackendConnection(ServerPreConnectEvent event, Player player, String targetServerName) {
        String playerIp = PlayerAddressUtils.getPlayerIp(player);
        boolean isAuthorized = authCache.isPlayerAuthorized(player.getUniqueId(), playerIp);

        // DODATKOWA WERYFIKACJA - sprawdź aktywną sesję z walidacją IP i timeout
        boolean hasActiveSession = authCache.hasActiveSession(player.getUniqueId(), player.getUsername(),
                playerIp, settings.getSessionTimeoutMinutes());

        // WERYFIKUJ UUID z bazą danych dla maksymalnego bezpieczeństwa - delegate to handler
        boolean uuidMatches = uuidVerificationHandler.verifyPlayerUuid(player);

        if (!isAuthorized || !hasActiveSession || !uuidMatches) {
            handleUnauthorizedConnection(event, player, targetServerName, isAuthorized, hasActiveSession, uuidMatches, playerIp);
        } else {
            // ✅ WSZYSTKIE WERYFIKACJE PRZESZŁY - POZWÓL
            logger.debug("\u2705 Autoryzowany gracz {} idzie na {} (sesja: OK, UUID: OK)",
                    player.getUsername(), targetServerName);
        }
    }

    private void handleUnauthorizedConnection(ServerPreConnectEvent event, Player player, String targetServerName,
                                            boolean isAuthorized, boolean hasActiveSession, boolean uuidMatches, String playerIp) {
        // ❌ NIE AUTORYZOWANY LUB BRAK SESJI LUB UUID MISMATCH
        String reason = resolveBlockReason(isAuthorized, hasActiveSession);

        if (logger.isDebugEnabled()) {
            logger.debug(messages.get("player.blocked.unauthorized", player.getUsername(), targetServerName, reason, playerIp));
        }

        event.setResult(ServerPreConnectEvent.ServerResult.denied());

        player.sendMessage(Component.text()
                .content("❌ ")
                .color(NamedTextColor.RED)
                .append(Component.text(messages.get("auth.must_login"))
                        .color(NamedTextColor.RED))
                .build());

        // Jeśli UUID mismatch - usuń z cache dla bezpieczeństwa
        if (!uuidMatches) {
            authCache.removeAuthorizedPlayer(player.getUniqueId());
            authCache.endSession(player.getUniqueId());
        }
    }

    /**
     * Handles server connected event.
     * Logs player transfers between servers and sends appropriate messages.
     * For verified players connecting to PicoLimbo, triggers auto-transfer to backend.
     */
    @Subscribe(priority = -200) // LAST priority
    public void onServerConnected(ServerConnectedEvent event) {
        try {
            Player player = event.getPlayer();
            String serverName = event.getServer().getServerInfo().getName();

            logger.debug("ServerConnectedEvent for player {} -> server {}",
                    player.getUsername(), serverName);

            if (!serverName.equals(settings.getPicoLimboServerName())) {
                handleBackendConnection(player, serverName);
            } else {
                handlePicoLimboConnection(player);
            }
        } catch (Exception e) {
            logger.error("Error in ServerConnected", e);
        }
    }

    private void handleBackendConnection(Player player, String serverName) {
        if (logger.isDebugEnabled()) {
            logger.debug(AUTH_MARKER, messages.get("player.connected.backend"),
                    player.getUsername(), serverName);
        }
        player.sendMessage(Component.text(messages.get("general.welcome.full"), NamedTextColor.GREEN));
    }

    private void handlePicoLimboConnection(Player player) {
        if (logger.isDebugEnabled()) {
            logger.debug(AUTH_MARKER, "ServerConnected to PicoLimbo: {}", player.getUsername());
        }

        String playerIp = PlayerAddressUtils.getPlayerIp(player);
        if (authCache.isPlayerAuthorized(player.getUniqueId(), playerIp)) {
            triggerAutoTransfer(player);
            return;
        }

        sendAuthInstructions(player);
    }

    private void triggerAutoTransfer(Player player) {
        if (logger.isDebugEnabled()) {
            logger.debug("Gracz {} jest zweryfikowany w cache - uruchamiam auto-transfer na backend",
                    player.getUsername());
        }
        connectionManager.autoTransferFromPicoLimboToBackend(player);
    }

    private void sendAuthInstructions(Player player) {
        player.sendMessage(Component.text(messages.get("auth.header"), NamedTextColor.GOLD));

        databaseManager.findPlayerByNickname(player.getUsername())
                .thenAccept(dbResult -> sendAuthPrompt(player, dbResult))
                .exceptionally(e -> {
                    logger.error("Error sending auth prompt for {}", player.getUsername(), e);
                    return null;
                });
    }

    private void sendAuthPrompt(Player player, DbResult<RegisteredPlayer> dbResult) {
        if (dbResult.isDatabaseError()) {
            player.sendMessage(Component.text(messages.get("auth.prompt.generic"), NamedTextColor.YELLOW));
            return;
        }

        RegisteredPlayer registeredPlayer = dbResult.getValue();
        if (registeredPlayer != null) {
            player.sendMessage(Component.text(messages.get("auth.account_exists"), NamedTextColor.GREEN));
        } else {
            player.sendMessage(Component.text(messages.get("auth.first_time"), NamedTextColor.AQUA));
        }
    }


}
