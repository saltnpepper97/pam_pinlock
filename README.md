# 🔒 pam_pinlock

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](https://github.com/saltnpepper97/pam_pinlock)
[![Language: C](https://img.shields.io/badge/language-C-blue.svg)](https://en.wikipedia.org/wiki/C_(programming_language))
[![PAM Compatible](https://img.shields.io/badge/PAM-compatible-orange.svg)](https://linux.die.net/man/8/pam)
[![Hyprland](https://img.shields.io/badge/Hyprland-supported-purple.svg)](https://hyprland.org/)
[![Security](https://img.shields.io/badge/security-Argon2-red.svg)](https://github.com/P-H-C/phc-winner-argon2)

> A secure, PIN-based authentication module for Linux, fully compatible with PAM and integrated with Hyprland via hyprlock. Protect your lock screen with a simple, fast PIN.

---

## ✨ Features

- 🛡️ **PAM Integration** — Works seamlessly with system login, su, and other PAM-aware services
- 🔐 **PIN Authentication** — Quick and memorable authentication method
- 🏋️ **Argon2 Hashing** — Industry-standard secure PIN storage with salt
- ⚡ **CLI Management** — Easily manage PINs with the intuitive `pinlockctl` utility
- 🚀 **Lightweight** — Minimal resource footprint and fast authentication
- 🔧 **Easy Setup** — Simple configuration and installation process

## 🎯 Overview

**pam_pinlock** revolutionizes your login experience by allowing users to authenticate using a PIN instead of a traditional password. This module combines the speed and convenience of PIN entry with enterprise-grade security through Argon2 password hashing.

Perfect for:
- **Lock screen authentication** with hyprlock
- **Quick system access** without compromising security  
- **Streamlined workflows** for frequent authentication
- **Multi-factor setups** as an additional auth layer

---

## 📋 Prerequisites

Before installing pam_pinlock, ensure your system meets these requirements:

| Requirement | Description |
|-------------|-------------|
| **OS** | Linux with PAM support |
| **Compiler** | GCC or compatible C compiler |
| **Libraries** | libpam-dev, libargon2-dev |
| **Build Tools** | make, git |

### 📦 Dependency Installation

**Debian/Ubuntu:**
```bash
sudo apt update && sudo apt install build-essential libpam0g-dev libargon2-dev git
```

**Fedora/RHEL:**
```bash
sudo dnf install gcc make pam-devel libargon2-devel git
```

**Arch Linux:**
```bash
sudo pacman -S base-devel pam argon2 git
```

---

## 🚀 Installation

### Quick Install
```bash
# Clone the repository
git clone https://github.com/saltnpepper97/pam_pinlock.git
cd pam_pinlock

# Build and install
make
sudo make install
make clean
```

### Manual Build Steps
```bash
# Compile the module
gcc -fPIC -c pam_pinlock.c -o pam_pinlock.o
gcc -shared pam_pinlock.o -lpam -largon2 -o pam_pinlock.so

# Install to system
sudo cp pam_pinlock.so /lib/x86_64-linux-gnu/security/
sudo cp pinlockctl /usr/local/bin/
sudo chmod +x /usr/local/bin/pinlockctl
```

---

## ⚙️ Configuration

### 1️⃣ PAM Configuration

Add pam_pinlock to your desired PAM service files:

**For Hyprlock** (`/etc/pam.d/hyprlock`):
```text
#%PAM-1.0
auth    sufficient  pam_pinlock.so
auth    include     system-auth
```

**For System-wide** (`/etc/pam.d/common-auth`):
```text
auth    [success=1 default=ignore]  pam_pinlock.so
# ... other auth modules
```

### 2️⃣ PIN Management

The `pinlockctl` utility provides comprehensive PIN management:

```bash
# 🔐 Set up a new PIN (interactive)
pinlockctl enroll

# ✅ Check PIN status and hash info  
pinlockctl status

# 🗑️ Remove existing PIN
pinlockctl remove
```
---

## 🎮 Usage

### Hyprland Integration
Lock your session and authenticate with your PIN:
```bash
# Lock screen with hyprlock
hyprlock

# Enter your PIN when prompted
# PIN: ****
```

### System Authentication
Use your PIN anywhere PAM authentication occurs:
- `sudo` commands
- User switching (`su`)
- Login screens
- Screen unlock

---

## 🔒 Security Features

- **🧂 Salted Hashing** — Each PIN uses a unique salt
- **⚡ Argon2id** — Memory-hard hashing resistant to GPU attacks  
- **🛡️ Secure Storage** — PINs stored in protected system locations
- **🚫 No Plaintext** — PINs never stored in readable form
- **⏱️ Rate Limiting** — Built-in protection against brute force

---

## 🤝 Contributing

We welcome contributions! Here's how to get started:

### Development Setup
```bash
# Fork and clone your fork
git clone https://github.com/YOUR_USERNAME/pam_pinlock.git
cd pam_pinlock

# Create feature branch
git checkout -b feature/awesome-enhancement

# Make changes and test
make test

# Commit and push
git commit -m "Add awesome enhancement"
git push origin feature/awesome-enhancement
```

### 📝 Contribution Guidelines
- Follow the existing code style
- Add tests for new features
- Update documentation as needed
- Ensure security best practices

Please read our [Code of Conduct](CODE_OF_CONDUCT.md) before contributing.

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **PAM Framework** — For providing the authentication infrastructure
- **Argon2** — For secure password hashing
- **Hyprland** — For the excellent Wayland compositor
- **Contributors** — Thank you to all who help improve this project!

---

<div align="center">
  
**⭐ If you find pam_pinlock helpful, please star the repository! ⭐**

[![GitHub stars](https://img.shields.io/github/stars/saltnpepper97/pam_pinlock.svg?style=social&label=Star)](https://github.com/saltnpepper97/pam_pinlock/stargazers)

</div>
