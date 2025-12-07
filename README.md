# VeloAuth v1.0.1

[![Modrinth](https://img.shields.io/badge/Modrinth-00AF5C?style=for-the-badge&logo=modrinth&logoColor=white)](https://modrinth.com/plugin/veloauth)
[![Discord](https://img.shields.io/badge/Discord-5865F2?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/e2RkPbc3ZR)

**Complete Velocity Authentication Plugin** with BCrypt, Virtual Threads and multi-database support.

## Quick Start (5 minutes)

1. **Install:** Copy `veloauth-1.0.1.jar` to `plugins/`
2. **Configure velocity.toml:**
   ```toml
   [servers]
   lobby = "127.0.0.1:25566"  # PicoLimbo
   survival = "127.0.0.1:25565"  # Backend
   
   try = ["survival"]  # Send players here after login
   ```
3. **Configure config.yml:** Set database (H2 works out-of-box)
4. **Restart Velocity** - Ready!

## Description

VeloAuth is an **authorization manager for Velocity proxy** that handles player transfers between Velocity, PicoLimbo and backend servers. The plugin supports all authorization operations on the proxy.

### Key Features:
- ✅ **Authorization Cache** - logged in players bypass login
- ✅ **Premium Cache TTL** - 24-hour expiration with background refresh
- ✅ **Transfer via Velocity** - control transfers between servers
- ✅ **Proxy Commands** - `/login`, `/register`, `/changepassword`
- ✅ **BCrypt hashing** - secure password storage (cost 10)
- ✅ **LimboAuth Compatible** - shared database compatibility
- ✅ **Premium and Cracked** - support for both player types
- ✅ **Virtual Threads** - efficient I/O (Java 21+)
- ✅ **Graceful Shutdown** - proper cleanup with timeout handling
- ✅ **Multi-database** - PostgreSQL, MySQL, H2, SQLite

## Test Server

2b2t.pl

## Requirements

- **Java 21+** (Virtual Threads)
- **Velocity API 3.4.0-SNAPSHOT+**
- **Database**: PostgreSQL 12+, MySQL 8.0+, H2, or SQLite
- **PicoLimbo** or other lobby server

## Installation

### 1. Download

Download from releases

### 2. Install on Velocity
1. Copy `VeloAuth-1.0.0.jar` to `plugins/`
2. Start Velocity - `config.yml` will be created
3. Configure database in `plugins/VeloAuth/config.yml`
4. Restart Velocity

### 3. PicoLimbo Configuration
Add PicoLimbo to `velocity.toml`:
```toml
[servers]
lobby = "127.0.0.1:25566"  # PicoLimbo (auth server)
survival = "127.0.0.1:25565"  # Backend server

try = ["lobby", "survival"]  # Order matters for lobby redirect
```

**Important:** The `try` configuration controls where players are sent after authentication. VeloAuth will:
1. Try servers in the order specified in `try` list
2. Skip the PicoLimbo server automatically  
3. Use the first available server from the list
4. Fallback to any available backend server if none in `try` are reachable

## Configuration

### config.yml
```yaml
# VeloAuth Configuration
database:
  storage-type: MYSQL  # MYSQL, POSTGRESQL, H2, SQLITE
  hostname: localhost
  port: 3306
  database: veloauth
  user: veloauth
  password: ""
  connection-pool-size: 20
  max-lifetime-millis: 1800000

cache:
  ttl-minutes: 60
  max-size: 10000
  cleanup-interval-minutes: 5
  premium-ttl-hours: 24  # Premium status cache expiration (default: 24 hours)
  premium-refresh-threshold: 0.8  # Background refresh at 80% TTL (default: 0.8)

picolimbo:
  server-name: lobby
  timeout-seconds: 300

security:
  bcrypt-cost: 10
  bruteforce-max-attempts: 5
  bruteforce-timeout-minutes: 5
  ip-limit-registrations: 3
  min-password-length: 4
  max-password-length: 72

premium:
  check-enabled: true
  online-mode-need-auth: false
  resolver:
    mojang-enabled: true
    ashcon-enabled: true
    wpme-enabled: false
    request-timeout-ms: 400
```

## Usage

### Player Commands

| Command | Description | Restrictions |
|---------|-------------|--------------|
| `/register <password> <confirm>` | Register new account | Cannot use premium nicknames |
| `/login <password>` | Login to account | Works for both premium/cracked |
| `/changepassword <old> <new>` | Change password | Must be logged in |

### Admin Commands

| Command | Permission | Description |
|---------|------------|-------------|
| `/unregister <nickname>` | `veloauth.admin` | Remove player account (resolves conflicts) |
| `/vauth reload` | `veloauth.admin` | Reload configuration |
| `/vauth cache-reset [player]` | `veloauth.admin` | Clear cache |
| `/vauth stats` | `veloauth.admin` | Show statistics |
| `/vauth conflicts` | `veloauth.admin` | List nickname conflicts |

## Authorization Algorithm

### 1. Player joins Velocity
```
ConnectionEvent → VeloAuth checks cache
├─ Cache HIT → Verification → Forward backend
└─ Cache MISS → Transfer to PicoLimbo
```

### 2. Nickname Protection (USE_OFFLINE Strategy)
VeloAuth protects nickname ownership with intelligent conflict resolution:

#### Premium Nickname Protection
```
Is nickname premium? → Check if already registered by cracked player
├─ NOT REGISTERED → Allow premium registration (nickname reserved for premium)
├─ ALREADY REGISTERED → Enter CONFLICT MODE
│  ├─ Premium player can login with cracked password (temporary access)
│  └─ Admin must resolve conflict or player changes nickname on Mojang.com
└─ CRACKED PLAYER tries premium nickname → BLOCK registration
```

#### Conflict Resolution Flow
1. **Premium player** tries nickname owned by **cracked player**:
   - System detects conflict
   - Shows resolution options to premium player
   - Allows temporary login with cracked password
   - Admin can resolve conflict or player changes nickname

2. **Cracked player** tries **premium nickname**:
   - Registration blocked immediately
   - Must choose different nickname

3. **Admin tools** for conflict management:
   - `/vauth conflicts` - List all active conflicts
   - `/unregister <nickname>` - Remove conflicted account

#### Quick Reference: Decision Table

| Player Type | Action | Result |
|-------------|--------|--------|
| **Cracked** | Tries premium nickname | ❌ BLOCKED - must choose different nickname |
| **Premium** | Nickname already owned by cracked | ⚠️ CONFLICT MODE - can login with cracked password temporarily |
| **Admin** | `/vauth conflicts` | 📋 Lists all active conflicts |
| **Admin** | `/unregister <nick>` | 🗑️ Removes conflicted account, resolves conflict |

#### Common Scenarios

**Scenario 1: Premium player "Notch" joins, nickname already registered by cracked player**
```
Real Notch (premium) joins server
↓
System detects: "Notch" already registered by cracked player
↓
Shows message: "⚠️ Nickname conflict! This nickname is used by an offline player."
↓
Options:
1. Login with cracked player's password (temporary access)
2. Change nickname on Mojang.com to regain premium access
```

**Scenario 2: Cracked player tries to register premium nickname**
```
Cracked player tries: /register NotchPassword NotchPassword
↓
System detects: "Notch" is premium nickname
↓
Blocks registration with error message
↓
Player must choose different nickname
```

**Scenario 3: Admin resolves conflict**
```
Admin runs: /vauth conflicts
↓
Shows: "⚠ Found 1 conflict: Notch (Status: OFFLINE)"
↓
Admin runs: /unregister Notch
↓
Account removed, premium player can register normally
```

### 3. Player on PicoLimbo
```
Player types: /login password or /register password password
↓
VELOCITY INTERCEPTS COMMAND
↓
1. SELECT HASH WHERE LOWERCASENICKNAME = LOWER(nickname)
2. BCrypt.verify(password, HASH)
├─ MATCH → UPDATE LOGINDATE + Cache + Forward backend
└─ NO MATCH → Brute force counter (max 5 attempts, timeout 5 min)
```

### 4. Player on Backend
```
ConnectionEvent → Cache HIT → Direct Backend
```

## Technical Details

### Performance
- **Cache HIT:** 0 DB queries, ~20ms
- **Cache MISS:** 1 DB query, ~100ms
- **/login:** 1 SELECT + 1 UPDATE, ~150ms (BCrypt)
- **/register:** 1 SELECT + 1 INSERT, ~200ms (BCrypt)

### Thread Safety
- **ConcurrentHashMap** for cache
- **ReentrantLock** for critical operations
- **Virtual Threads** for I/O operations

### Security
- **BCrypt cost 10** with salt (at.favre.lib 0.10.2)
- **Brute Force Protection** - 5 attempts / 5 minutes timeout
- **SQL Injection Prevention** - ORMLite prepared statements
- **Rate Limiting** - Velocity command rate limiting
- **IP Registration Limit** - Max 3 accounts per IP

## Premium Status Caching

VeloAuth implements intelligent premium status caching to minimize external API calls:

### Premium Cache Configuration
```yaml
cache:
  premium-ttl-hours: 24  # How long to cache premium status
  premium-refresh-threshold: 0.8  # Trigger background refresh at 80% TTL
```
events `RejectedExecutionException` errors during server shutdown.

## Compatibility

VeloAuth is **compatible** with LimboAuth database - ignores `TOTPTOKEN` and `ISSUEDTIME` fields.

### Migration from LimboAuth
1. Stop LimboAuth
2. Install VeloAuth
3. Configure the same database
4. Start Velocity - VeloAuth will automatically detect existing accounts

## Troubleshooting

### Common Issues

**Database Connection Failed**
```
ERROR/BASE error: Database connection failed
```
→ Check database credentials, ensure database is running, verify network connectivity

**Permission Denied**
```
You don't have permission to use this command
```
→ Ensure admin has `veloauth.admin` permission in Velocity config

**Players Stuck on PicoLimbo**
→ Check `try` configuration in velocity.toml, ensure backend servers are online

**Nickname Conflicts Not Working**
→ Verify premium checking is enabled, check Mojang API connectivity

### FAQ

**Q: Can cracked players use premium nicknames?**
A: No - VeloAuth blocks registration of premium nicknames by cracked players.

**Q: What happens when a premium player tries to use a nickname already registered by a cracked player?**
A: The system enters conflict mode, shows resolution options, and allows temporary login with the cracked password.

**Q: How do I resolve nickname conflicts?**
A: Use `/vauth conflicts` to list conflicts, then `/unregister <nickname>` to remove the conflicted account.

**Q: Why aren't players being sent to the correct server after login?**
A: Check your `try` configuration in velocity.toml - VeloAuth uses this order to select the destination server.

**Q: Can I migrate from LimboAuth?**
A: Yes - VeloAuth is fully compatible with LimboAuth database format.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Support

- **Discord:** [\[Server link\]](https://discord.gg/e2RkPbc3ZR)
- **Issues:** [GitHub Issues](https://github.com/rafalohaki/veloauth/issues)

---

**VeloAuth v1.0.1** - Complete Velocity Authentication Plugin  
Author: rafalohaki | Java 21 + Virtual Threads + BCrypt + Multi-DB