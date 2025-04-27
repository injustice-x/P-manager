## Overview

This C-based password manager provides secure credential storage and retrieval via AES encryption, SHA3 hashing, and a simple JSON-backed vault format . It features user creation, login, entry addition, viewing, editing, and searching—all through a clean command-line interface . The project follows GitHub README best practices by clearly outlining installation, usage, and contribution guidelines .

## Features

- **User Management**: Create new users with salted SHA3-256 hashes and derive AES keys via PBKDF2 .
- **Secure Vault**: Encrypts credential entries (name, username, password, website) in AES-CBC with a random IV; decrypts on login .
- **CRUD Operations**: Add, view, edit, and search entries in-place, preserving original data on errors .
- **Random Password Generation**: Built-in generator supports custom lengths, using a broad charset of letters, digits, and symbols .
- **Command-Line Interface**: Utilizes `getopt` for argument parsing (`-f <filepath>`) and a numbered menu for vault operations .

## Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/injustice-x/p-manager.git
   cd p-manager
   ```
2. **Install dependencies**

   - OpenSSL (for `PKCS5_PBKDF2_HMAC`)
   - cjson for Json support
   - A C compiler supporting C11 (`gcc`, `clang`)

3. **Build**
   ```bash
   mkdir build
   cd build
   cmake ..
   make
   ```

## Usage

```bash
./main -f vault.dat
```
