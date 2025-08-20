# 🔒 pam_pinlock

A secure, PIN-based authentication module for Linux, fully compatible with PAM and integrated with Hyprland via hyprlock. Protect your lock screen with a simple, fast PIN.

# Features

- 🛡️ **PAM Integration:** Works with system login, su and other PAM aware services
- 🔐 **PIN Login:** Quick and memorable authentication
- 🏋️ **Argon2 Hashing:** Industy-standard secure PIN storage
- ⚡ **CLI Tool:** Easily add, remove or check PINs with `pinlockctl`

# Overview

pam_pinlock lets users log in using a PIN instead of a password, combining speed, security, and convenience. It works with all PAM-aware services and enhances your lock screen with hyprlock.

Secure, fast, and effortless—logging in has never been easier.

---

## Prerequisites

Before installing pam_pinlock, ensure you have:

- Linux system with PAM support
- Dependencies: gcc, make, libpam-dev, libargon2-dev  
- Git for cloning the repository  

Debian/Ubuntu installation example:

```bash
sudo apt update && sudo apt install build-essential libpam0g-dev libargon2-dev git
```

## Installation

Clone the repository and build:

```bash
git clone https://github.com/saltnpepper97/pam_pinlock.git
cd pam_pinlock
make
make install
make clean
sudo make install
e5aef74 (Fixed README.md)
```

> Note: `sudo` may be required for system-wide installation.

## Configuration

### PAM Setup

Add pam_pinlock to your PAM configuration (e.g., /etc/pam.d/hyprlock or /etc/pam.d/common-auth):

```text
auth sufficient pam_pinlock.so
```

### PIN Management

Use pinlockctl to set, verify, or remove PINs:

```bash
# Set a new PIN
pinlockctl enroll

# Verify PIN
pinlockctl status

# Remove PIN
pinlockctl remove
```

## Usage

Lock your Hyprland session with hyprlock and enter your PIN:

```bash
hyprlock
```

## Contributing

Contributions are welcome!  

Fork the repository, create a feature branch, commit, push, and open a pull request:

```bash
git checkout -b feature/awesome-feature
git commit -m "Add awesome feature"
git push origin feature/awesome-feature
```

Please follow the Contributor Covenant Code of Conduct.

## License

This project is licensed under the MIT License – see the LICENSE file for details.
