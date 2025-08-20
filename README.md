# pam_pinlock 🔒

A modern, secure, and beautiful PIN-based authentication module for Linux, integrated with **Hyprland** via `hyprlock`. Because sometimes you just want your lock screen to be secure *and* stylish.  

---

## Features

- ✅ **PAM module**: Works with system login, su, and any PAM-aware service.  
- 🔑 **PIN-based authentication**: Simple, fast, and memorable.  
- 🎨 **Beautiful UI**: Fully configurable with `hyprlock`—fonts, colors, blur, shadows, and animations.  
- 🛡 **Argon2 hashing**: Strong, modern password hashing for your PINs.  
- ⚡ **Lightweight CLI**: Manage PINs easily with `pinlockctl`.  
- 🖼 **Custom backgrounds**: Blur screenshots, wallpapers, or solid colors.  
- ⏱ **Animations**: Fade in/out, bouncy slides, input dot animations, and more.  

---

## Installation

Build and install using `make`:

```bash
git clone https://github.com/saltnpepper97/pam_pinlock.git
cd pam_pinlock
make clean
make install
