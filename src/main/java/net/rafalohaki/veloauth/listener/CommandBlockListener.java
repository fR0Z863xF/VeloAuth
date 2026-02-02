package net.rafalohaki.veloauth.listener;

import com.velocitypowered.api.event.PostOrder;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.command.CommandExecuteEvent;
import com.velocitypowered.api.proxy.Player;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import net.rafalohaki.veloauth.cache.AuthCache;
import net.rafalohaki.veloauth.config.Settings;
import net.rafalohaki.veloauth.i18n.Messages;
import net.rafalohaki.veloauth.util.PlayerAddressUtils;
import org.slf4j.Logger;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Listener that blocks command execution for unauthenticated players.
 * Allows authentication commands (/login, /register, /changepassword) to pass through.
 */
public class CommandBlockListener {

    private final AuthCache authCache;
    private final Settings settings;
    private final Messages messages;
    private final Logger logger;

    /**
     * Commands that are always allowed even when not authenticated.
     * These are the authentication commands themselves.
     */
    private static final Set<String> ALLOWED_COMMANDS = new HashSet<>(Arrays.asList(
            "login",
            "register",
            "changepassword",
            "l",  // Common alias for /login
            "reg" // Common alias for /register
    ));

    /**
     * Creates a new CommandBlockListener.
     *
     * @param authCache Cache for checking authentication status
     * @param settings  Plugin settings
     * @param messages  i18n message system
     * @param logger    Logger instance
     */
    public CommandBlockListener(AuthCache authCache, Settings settings, Messages messages, Logger logger) {
        this.authCache = authCache;
        this.settings = settings;
        this.messages = messages;
        this.logger = logger;
    }

    /**
     * Handles command execution event.
     * Blocks commands for unauthenticated players if feature is enabled.
     *
     * @param event CommandExecuteEvent
     */
    @Subscribe(order = PostOrder.FIRST)
    public void onCommandExecute(CommandExecuteEvent event) {
        // Check if feature is enabled
        if (!settings.isBlockCommandsBeforeAuth()) {
            return;
        }

        // Only check for players (not console)
        if (!(event.getCommandSource() instanceof Player player)) {
            return;
        }

        // Get command name (first word of the command)
        String command = event.getCommand();
        String commandName = extractCommandName(command);

        // Allow authentication commands
        if (isAllowedCommand(commandName)) {
            return;
        }

        // Check if player is authenticated
        String playerIp = PlayerAddressUtils.getPlayerIp(player);
        boolean isAuthorized = authCache.isPlayerAuthorized(player.getUniqueId(), playerIp);

        if (!isAuthorized) {
            // Block command and notify player
            event.setResult(CommandExecuteEvent.CommandResult.denied());
            
            player.sendMessage(Component.text(
                    messages.get("command.blocked.not_authenticated"),
                    NamedTextColor.RED
            ));

            if (logger.isDebugEnabled()) {
                logger.debug("Blocked command '{}' from unauthenticated player: {}", 
                        commandName, player.getUsername());
            }
        }
    }

    /**
     * Extracts the command name from the full command string.
     * Handles commands with and without leading slash.
     *
     * @param command Full command string
     * @return Command name (lowercase, without slash)
     */
    private String extractCommandName(String command) {
        if (command == null || command.isEmpty()) {
            return "";
        }

        // Remove leading slash if present
        String normalized = command.startsWith("/") ? command.substring(1) : command;

        // Get first word (command name)
        int spaceIndex = normalized.indexOf(' ');
        String commandName = spaceIndex > 0 ? normalized.substring(0, spaceIndex) : normalized;

        return commandName.toLowerCase();
    }

    /**
     * Checks if a command is in the allowed list.
     *
     * @param commandName Command name to check
     * @return true if command is allowed
     */
    private boolean isAllowedCommand(String commandName) {
        return ALLOWED_COMMANDS.contains(commandName);
    }
}
