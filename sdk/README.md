# 📦 PocketBase Passkey SDK

[![NPM Version](https://img.shields.io/npm/v/pocketbase-passkey.svg)](https://www.npmjs.com/package/pocketbase-passkey)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A lightweight, TypeScript-first SDK to integrate **Passkey (WebAuthn)** authentication with **PocketBase**.

## Features

- **🚀 One-Click Registration & Login**: High-level methods to skip the "Begin/Finish" boilerplate.
- **🔐 PocketBase Native**: Seamlessly integrates with the official PocketBase SDK to handle `authStore` automatically.
- **🛠️ Type-Safe**: Written in TypeScript with full JSDoc support for IntelliSense.
- **⚠️ Custom Error Classes**: Easily handle user cancellations and verification failures.

## Installation

```bash
npm install pocketbase-passkey
```

## Basic Usage

### Initialize the SDK

```typescript
import { PocketBasePasskey } from "pocketbase-passkey";
import PocketBase from "pocketbase";

// 1. Initialize official PocketBase SDK
const pb = new PocketBase("http://localhost:8090");

// 2. Initialize Passkey SDK (passing the pb instance)
const sdk = new PocketBasePasskey({ pb });
```

### One-Click Register

Registers a new passkey for the current user ID.

```typescript
try {
  const result = await sdk.register("user_record_id");
  console.log("Passkey registered!");
} catch (err) {
  console.error("Registration failed", err);
}
```

### One-Click Login

Authenticates the user and **automatically** populates `pb.authStore`.

```typescript
try {
  const result = await sdk.login("user_record_id");
  // pb.authStore.token is now saved and valid!
  console.log("Authenticated as:", pb.authStore.model.email);
} catch (err) {
  if (err.name === "PasskeyCancelledError") {
    console.log("User closed the biometric dialog");
  }
}
```

## Advanced Error Handling

The SDK provides specific error classes for robust UX:

```typescript
import {
  PasskeyCancelledError,
  PasskeyVerificationError,
} from "pocketbase-passkey";

try {
  await sdk.login(userId);
} catch (err) {
  if (err instanceof PasskeyCancelledError) {
    // User clicked "Cancel" or closed the Face ID prompt
  } else if (err instanceof PasskeyVerificationError) {
    // Server rejected the passkey signature
  }
}
```

## Support & Integration

This SDK is designed to work with the [PocketBase Passkey Server](https://github.com/your-username/pocketbase-passkey).

## License

MIT
