package net.rafalohaki.veloauth.constants;

/**
 * Constants for commonly used strings to avoid duplication.
 * Improves maintainability and reduces SonarCloud duplication warnings.
 */
public final class StringConstants {

    private StringConstants() {
        // Utility class - prevent instantiation
    }

    // Database error messages
    public static final String DATABASE_ERROR_MESSAGE = "Wystąpił błąd bazy danych. Spróbuj ponownie później.";
    public static final String DATABASE_SAVE_ERROR_MESSAGE = "Wystąpił błąd podczas zapisu. Spróbuj ponownie.";
    public static final String DATABASE_ERROR_PREFIX = "Błąd bazy danych: ";

    // Registration timeout message
    public static final String REGISTRATION_TIMEOUT_MESSAGE = "Timeout rejestracji - spróbuj ponownie";

    // Security messages
    public static final String BRUTE_FORCE_BLOCK_REASON = "nieautoryzowany";
    public static final String NO_ACTIVE_SESSION_REASON = "brak aktywnej sesji";
    public static final String UUID_MISMATCH_REASON = "UUID mismatch";
}