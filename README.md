# 🔒 pam_pinlock

A modern, secure, and stylish PIN-based authentication module for Linux, seamlessly integrated with Hyprland via hyprlock. Protect your lock screen with a PIN while keeping it visually stunning!

## Overview

pam_pinlock brings a fast, secure, and customizable PIN-based authentication experience to Linux systems. Designed to work with PAM-aware services (e.g., system login, su) and paired with hyprlock for a beautiful lock screen, it combines security with aesthetics.

## Features

🛡️ PAM Integration: Works with system login, su, and other PAM-aware services.  
🔐 PIN Authentication: Quick, simple, and memorable PIN-based login.  
🏋️ Argon2 Hashing: Industry-standard secure hashing for your PINs.  
⚡ Lightweight CLI: Manage PINs effortlessly using `pinlockctl`.   

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
