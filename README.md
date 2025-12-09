<p align="center">
  <img src="https://cdn.modrinth.com/data/cached_images/a31eec688d48cffe2770bd961e5d134c71b8b662.png" alt="VeloAuth Logo">
</p>

# VeloAuth

[![Modrinth](https://img.shields.io/badge/Modrinth-00AF5C?style=for-the-badge&logo=modrinth&logoColor=white)](https://modrinth.com/plugin/veloauth) [![Discord](https://img.shields.io/badge/Discord-5865F2?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/e2RkPbc3ZR)

**Simple, Fast, and Secure Authentication for Velocity Proxy.**  
*Prosty, szybki i bezpieczny plugin do autoryzacji dla Velocity.*

---

## ❓ What is this? / Co to jest?

VeloAuth is a plugin that protects your server. It forces players to **login** or **register** before they can play. It supports **Premium** (no login needed) and **Cracked** (login required) players automatically!

*VeloAuth to plugin, który chroni twój serwer. Wymusza na graczach **logowanie** lub **rejestrację** zanim zaczną grać. Obsługuje graczy **Premium** (bez logowania) i **Non-Premium** (z logowaniem) automatycznie!*

---

## ✨ Features / Funkcje

*   ✅ **Secure Passwords** - Uses BCrypt (very safe / bardzo bezpieczne).
*   ✅ **Auto-Login** - Premium players join instantly (Gracze Premium wchodzą bez hasła).
*   ✅ **No Lag** - Built on Java 21 Virtual Threads (0% lag).
*   ✅ **Multi-Database** - MySQL, PostgreSQL, SQLite, H2.
*   ✅ **Limbo Support** - Unlogged players stay in a safe "limbo" server (PicoLimbo).
*   ✅ **Translations** - Available in 7 languages!

---

## 🌍 Supported Languages / Wspierane Języki

We speak your language! / Mówimy w twoim języku!

| Flag | Language | Code |
| :---: | :--- | :---: |
| 🇺🇸 | English | `en` |
| 🇵🇱 | Polish | `pl` |
| 🇩🇪 | German | `de` |
| 🇫🇷 | French | `fr` |
| 🇷🇺 | Russian | `ru` |
| 🇹🇷 | Turkish | `tr` |
| 🇸🇮 | Slovenian | `si` |

---

## 🚀 Installation (Easy Mode) / Instalacja

### 1. Requirements / Wymagania
*   **Java 21** or newer.
*   **Velocity** Proxy Server.
*   **PicoLimbo** (recommended for the lobby).

### 2. Setup / Konfiguracja
1.  **Download** `VeloAuth.jar`.
2.  **Drop it** into your `plugins/` folder on Velocity.
3.  **Start** the server.
4.  **Edit** `plugins/VeloAuth/config.toml` if you need to change database (Default: H2 - works instantly).

### 3. Velocity Config (`velocity.toml`)
Make sure your servers are set up correctly.  
*Upewnij się, że twoje serwery są dobrze ustawione.*

```toml
[servers]
lobby = "127.0.0.1:25566"    # PicoLimbo (Auth Server)
survival = "127.0.0.1:25565" # Your Main Server

# Important! / Ważne!
try = ["survival"] 
# VeloAuth will send players to 'survival' AFTER they login.
# VeloAuth wyśle graczy na 'survival' PO zalogowaniu.
```

---

## 📜 Commands / Komendy

| Command | Usage | Description |
| :--- | :--- | :--- |
| **/login** | `/login <pass>` | Login to the server. |
| **/register** | `/register <pass> <pass>` | Create a new account. |
| **/changepassword** | `/changepassword <old> <new>` | Change password. |
| **/unregister** | `/unregister <player>` | (Admin) Delete player account. |
| **/vauth reload** | `/vauth reload` | (Admin) Reload config. |
| **/vauth conflicts** | `/vauth conflicts` | (Admin) Check name conflicts. |

---

## 🛠️ Configuration / Konfiguracja

Simple explanation of `config.toml`:

```yaml
database:
  storage-type: H2  # Options: MYSQL, POSTGRESQL, SQLITE, H2
  # For MySQL fill out hostname, user, password below...

cache:
  ttl-minutes: 60   # How long to remember login (minutes)
  premium-ttl-hours: 24 # How often to check Premium status

picolimbo:
  server-name: lobby # Name of your limbo server in velocity.toml
```

---

## 🆘 Support

Need help? Found a bug?  
**Join Discord:** [https://discord.gg/e2RkPbc3ZR](https://discord.gg/e2RkPbc3ZR)
