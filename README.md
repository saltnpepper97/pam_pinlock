# 🔒 pam_pinlock
<div align="center">
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge" alt="License: MIT">
  <img src="https://img.shields.io/badge/build-passing-brightgreen?style=for-the-badge" alt="Build Status">
  <img src="https://img.shields.io/badge/PAM-compatible-orange?style=for-the-badge" alt="PAM Compatible">
  <img src="https://img.shields.io/badge/Hyprland-supported-purple?style=for-the-badge" alt="Hyprland">
  <img src="https://img.shields.io/badge/security-Argon2-red?style=for-the-badge" alt="Security">
  <img src="https://img.shields.io/badge/AUR-available-blue?style=for-the-badge" alt="AUR">
</div>

> A secure, feature-rich PIN-based authentication module for Linux with rate limiting, account lockout protection, and comprehensive configuration options. Perfect for Hyprland's hyprlock and system-wide authentication.

---

## ✨ Features

- 🛡️ **PAM Integration** — Works seamlessly with login, sudo, su, and any PAM-aware service
- 🔐 **Secure PIN Authentication** — Fast, memorable authentication with enterprise-grade security
- 🏋️ **Argon2id Hashing** — Industry-standard password hashing with unique salts per user
- 🛑 **Rate Limiting** — Built-in brute force protection with configurable attempt limits
- 🔒 **PIN Lockout** — Optional temporary PIN lockout with configurable PAM failure behavior
- ⚙️ **Flexible Configuration** — System-wide and per-user configuration files
- 🎛️ **Advanced PIN Requirements** — Configurable length limits and character validation
- 📊 **Comprehensive Logging** — Detailed syslog integration with configurable verbosity
- ⚡ **CLI Management** — Full-featured `pinlockctl` utility for PIN and system management
- 🚀 **Lightweight & Fast** — Minimal resource footprint with optimized authentication
- 🔧 **Easy Setup** — Simple installation with intelligent path detection

## 🎯 Overview

**pam_pinlock** brings Windows Hello-style PIN authentication to Linux systems. Combining speed and convenience with robust security features, it's perfect for:

- **Hyprland hyprlock integration** — Secure, fast screen unlocking
- **System authentication** — Replace or supplement password authentication
- **Multi-factor setups** — Additional authentication layer
- **Frequent access scenarios** — Streamlined workflow without security compromise

---

## 📋 Prerequisites

| Requirement | Description |
|-------------|-------------|
| **OS** | Linux with PAM support (tested on Ubuntu, Fedora, Arch) |
| **Compiler** | GCC 7+ or compatible C compiler |
| **Libraries** | libpam-dev, libargon2-dev |
| **Build Tools** | make, git |
| **Permissions** | sudo access for installation |

### 📦 Dependency Installation

**Debian/Ubuntu:**
```bash
sudo apt update && sudo apt install build-essential libpam0g-dev libargon2-dev git
```

**Fedora/RHEL/CentOS:**
```bash
sudo dnf install gcc make pam-devel libargon2-devel git
```

**Arch Linux:**
```bash
sudo pacman -S base-devel pam argon2 git
```

---

## 🚀 Installation

### 📦 Arch Linux (AUR)

**Using an AUR helper (yay, paru, etc.):**
```bash
yay -S pam_pinlock
# or
paru -S pam_pinlock
```

**Manual AUR installation:**
```bash
git clone https://aur.archlinux.org/pam_pinlock.git
cd pam_pinlock
makepkg -si
```

### 🔨 Build from Source

**Quick Install:**
```bash
# Clone the repository
git clone https://github.com/saltnpepper97/pam_pinlock.git
cd pam_pinlock

# Build and install
make clean
make
sudo make install

# Set up configuration (optional)
sudo cp /etc/pinlock/examples/pinlock.conf /etc/pinlock.conf
sudo nano /etc/pinlock.conf
```

**Build Output:**
```
gcc -Wall -Wextra -O2 -fPIC -shared -o pam_pinlock.so pam_pinlock.c -lpam -largon2
gcc -Wall -Wextra -O2 -fPIC -o pinlockctl pinlockctl.c -largon2
Installing to PAM directory: /lib/x86_64-linux-gnu/security
Installation complete!
```

---

## ⚙️ Configuration

### 🔧 PIN Configuration (`/etc/pinlock.conf`)

Create and customize your global configuration:

```bash
sudo cp /etc/pinlock/examples/pinlock.conf /etc/pinlock.conf
sudo nano /etc/pinlock.conf
```

**Configuration Options:**
```ini
# PIN Storage
# Leave unset to use ~/.pinlock for each user
# Use an absolute root-managed directory for polkit or other root helper services
# pin_dir=/var/lib/pinlock

# User Configuration
# Disabled by default so user config cannot weaken system policy
allow_user_config=no

# PIN Requirements
min_length=6                 # Minimum PIN length
max_length=32               # Maximum PIN length  
require_digits_only=yes     # Allow only numeric PINs

# Rate Limiting
max_attempts=5              # Max attempts before rate limiting
rate_limit_window=60        # Time window in seconds
lockout_window=300          # How long to wait after rate limit

# PIN Lockout (disabled by default)
enable_lockout=no           # Enable temporary PIN lockout
lockout_duration=900        # Lockout duration in seconds
lockout_fails_auth=no       # If yes, lockout returns PAM_AUTH_ERR instead of fallback

# Logging
log_attempts=yes            # Log all authentication attempts
log_success=yes             # Log successful authentications
log_failures=yes            # Log failed attempts
debug=no                    # Enable debug logging
```

### 🔐 User-Specific Configuration

User-specific config is disabled by default so users cannot weaken system authentication policy. Administrators can enable it with `allow_user_config=yes`, after which users can override settings in `~/.pinlock/pinlock.conf`:
```bash
mkdir -p ~/.pinlock
cp /etc/pinlock/examples/pinlock.conf ~/.pinlock/pinlock.conf
nano ~/.pinlock/pinlock.conf
```

### 🛡️ PAM Integration

**For Hyprland hyprlock** (`/etc/pam.d/hyprlock`):
```pam
#%PAM-1.0
auth    sufficient  pam_pinlock.so
auth    include     system-auth
```

**For system-wide authentication** (`/etc/pam.d/common-auth` or `/etc/pam.d/system-auth`):
```pam
# Try PIN first, fallback to other methods
auth    sufficient    pam_pinlock.so
# ... existing auth modules
```

**For sudo with custom prompt** (`/etc/pam.d/sudo`):
```pam
auth    sufficient  pam_pinlock.so prompt="Admin PIN: "
auth    include     system-auth
```

**For polkit/KDE authentication prompts** (`/etc/pam.d/polkit-1`):
```pam
#%PAM-1.0
auth       sufficient   pam_pinlock.so prompt="PIN: "
auth       include      system-auth
account    include      system-auth
password   include      system-auth
session    include      system-auth
```

For polkit, a system PIN directory is recommended so the polkit helper can resolve the same PIN files as `pinlockctl`:
```bash
sudo install -d -m 700 /var/lib/pinlock
sudo nano /etc/pinlock.conf  # Set pin_dir=/var/lib/pinlock
sudo pinlockctl set alice
sudo pinlockctl check alice
```

If polkit still falls back to password auth, temporarily enable `debug=yes` in `/etc/pinlock.conf` or add `debug` to the PAM line, then check the logged PIN path with:
```bash
journalctl -b | grep pinlock
```
Remove `debug` again after testing.

---

## 🎮 Usage

### PIN Management with `pinlockctl`

```bash
# Set up a new PIN (prompts for username if not specified)
pinlockctl set [username]
pinlockctl enroll alice      # Set PIN for user 'alice'

# Check PIN status
pinlockctl status [username]
# Output: PIN enrolled for alice
#         Rate limiting data exists (check logs for lockout status)

# View current configuration
pinlockctl config [username]
# Shows complete config including requirements and security settings

# Check storage path, ownership, and permissions
pinlockctl check alice

# Clear rate limiting/unlock user
pinlockctl unlock alice

# Remove PIN and associated data
pinlockctl remove alice

# Get help
pinlockctl help
```

### Authentication Examples

**Hyprland Screen Lock:**
```
PIN (alice): ●●●●●●
# Authenticated successfully
```

**Sudo with PIN:**
```bash
sudo systemctl restart nginx
Admin PIN: ●●●●●●
# Command executed
```

**System Login:**
```
login: alice
PIN (alice): ●●●●●●
# Login successful
```

---

## 🔒 Security Features

### 🛡️ Cryptographic Security
- **Argon2id hashing** with unique salts per user
- **Memory-hard algorithm** resistant to GPU/ASIC attacks
- **Configurable work factors** for performance tuning
- **Secure memory handling** with explicit memory wiping

### 🚫 Brute Force Protection  
- **Rate limiting** with configurable attempt windows
- **Optional temporary PIN lockout** for repeated failures
- **Configurable PAM behavior** during PIN lockout: fallback or authentication failure
- **Detailed logging** of all authentication attempts

### 📁 Secure Storage
- **Protected file permissions** (0600) for PIN files
- **User-specific directories** (`~/.pinlock/`) or root-managed system storage (`/var/lib/pinlock`)
- **Atomic PIN file writes** to prevent corruption
- **Ownership, permission, and symlink checks** before authentication
- **No plaintext storage** — PINs never stored in readable form

### 🔍 Audit Trail
- **Comprehensive syslog integration**
- **Success/failure logging** with timestamps
- **Rate limit notifications**
- **Lockout alerts** for administrators

---

## 🔧 Advanced Usage

### Multiple Authentication Methods
```pam
# /etc/pam.d/login - Try PIN, fallback to password
auth    sufficient  pam_pinlock.so
auth    required    pam_unix.so
```

### Custom Prompts
```pam
auth    sufficient  pam_pinlock.so prompt="Secure PIN: "
auth    sufficient  pam_pinlock.so prompt="PIN for %u: "
```

### Debug Mode
```pam
auth    sufficient  pam_pinlock.so debug
```

### Monitoring
```bash
# Watch authentication logs
sudo tail -f /var/log/auth.log | grep pinlock

# Check rate limiting status
pinlockctl status $USER

# View system-wide PIN usage
sudo find /home -name "*.pin" -exec ls -la {} \;
```

---

## 🐛 Troubleshooting

### Common Issues

**PAM module not found:**
```bash
# Find your PAM directory
find /lib* /usr/lib* -name "pam_unix.so" -exec dirname {} \;
# Copy pam_pinlock.so to the correct directory
```

**Permission denied during setup:**
```bash
# Ensure proper permissions
chmod 700 ~/.pinlock/
chmod 600 ~/.pinlock/*.pin

# For system storage used by polkit
sudo install -d -m 700 /var/lib/pinlock
sudo pinlockctl check $USER
```

**Rate limiting activated:**
```bash
# Clear rate limiting
pinlockctl unlock $USER
```

**PIN not working:**
```bash
# Check configuration
pinlockctl config $USER

# Enable debug logging
sudo nano /etc/pinlock.conf  # Set debug=yes
# Check logs: sudo journalctl -u systemd-logind -f
```

### Log Analysis
```bash
# View authentication attempts
sudo grep "pinlock" /var/log/auth.log

# Monitor real-time
sudo tail -f /var/log/auth.log | grep pinlock
```

---

## 🤝 Contributing

We welcome contributions! Here's how to get involved:

### Development Setup
```bash
# Fork and clone
git clone https://github.com/YOUR_USERNAME/pam_pinlock.git
cd pam_pinlock

# Create feature branch
git checkout -b feature/your-enhancement

# Build and test
make clean && make
make test
./pinlockctl help

# Test PAM integration (safe test)
echo "auth sufficient $(pwd)/pam_pinlock.so debug" | sudo tee /tmp/test-pam
```

### 🎯 Areas for Contribution
- GUI PIN entry tools
- Platform compatibility
- Documentation improvements

### 📋 Contribution Guidelines
- Follow existing code style (K&R style, 4-space indents)
- Add comprehensive error handling
- Include security considerations
- Update documentation
- Test on multiple distributions

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

## 🔗 Related Projects

- [Hyprland](https://hyprland.org/) — Modern Wayland compositor
- [hyprlock](https://github.com/hyprwm/hyprlock) — Screen locker for Hyprland
- [PAM](https://www.linux-pam.org/) — Pluggable Authentication Modules
- [Argon2](https://github.com/P-H-C/phc-winner-argon2) — Password hashing library

---

## 🙏 Acknowledgments

- **PAM Framework** — For providing robust authentication infrastructure
- **PHC Argon2** — For secure, modern password hashing
- **Hyprland Community** — For inspiration and testing feedback
- **Linux Security Community** — For best practices and security guidance
- **Contributors** — Thank you to everyone who helps improve this project!

---

<div align="center">
  
**⭐ Star this repository if pam_pinlock enhances your Linux security! ⭐**

[![GitHub stars](https://img.shields.io/github/stars/saltnpepper97/pam_pinlock.svg?style=social&label=Star)](https://github.com/saltnpepper97/pam_pinlock/stargazers)

**🐛 Found a bug? 🚀 Have a feature idea?**  
[Open an issue](https://github.com/saltnpepper97/pam_pinlock/issues) or [contribute](https://github.com/saltnpepper97/pam_pinlock/pulls)!

</div>
