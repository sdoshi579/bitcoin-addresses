# Bitcoin Address Generator and Hierarchical Deterministic Wallet

## Overview

This project implements a **Bitcoin Address Generator** and a **Hierarchical Deterministic (HD) Wallet** system based on the [BIP-32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) standard. It provides functionality to generate various types of Bitcoin addresses and derive cryptographic keys in a hierarchical structure.

---

## Features

### 1. Bitcoin Address Generation

Generate different types of Bitcoin addresses such as:

1. **Pay to Public Key Hash (P2PKH)**: Legacy Bitcoin address format.
2. **Pay to Script Hash (P2SH)**: Enables multi-signature and custom scripts.
3. **Pay to Witness Public Key Hash (P2WPKH)**: SegWit (Bech32) address format for reduced transaction fees.
4. **Pay to Taproot (P2TR)**: Taproot address format for enhanced privacy and scalability.

### 2. Hierarchical Deterministic Wallet

- **Entropy and Recovery Codes**:
  - Generate cryptographically secure entropy.
  - Convert entropy into mnemonic recovery codes (BIP-39 style).
- **Seed Generation**:
  - Derive a cryptographic seed from recovery codes and an optional passphrase.
- **Master Key Derivation**:
  - Derive the master private key and chain code from the seed.
- **Child Key Derivation**:
  - Support for both **hardened** and **normal** child key derivation.
  - Handle complex derivation paths (e.g., `m/0'/1/2'`).
- **Public Key Derivation**:
  - Derive child public keys from parent public keys and chain codes.

---

## Example Usage

### Generate Bitcoin Addresses

Run the following command to generate Bitcoin addresses:

```go
go run main.go
```

The `main.go` file demonstrates how to generate Bitcoin addresses for a given ECC key pair.

### Derive Keys for a Path

The `GetChildKeyFromPath` function allows you to derive keys for a specific path.

```go
req := addresses.KeyDerivationRequest{
    MasterPrivateKey: masterPrivateKey,
    MasterChainCode:  masterChainCode,
    Path:             "m/0/0/0'",
}

resp, err := addresses.GetChildKeyFromPath(req)
if err != nil {
    fmt.Println("Error deriving key from path:", err)
    return
}

fmt.Printf("Derived key for path %s:\n", resp.Path)
fmt.Printf("Private Key: %x\n", resp.PrivateKey)
fmt.Printf("Public Key: %x\n", resp.PublicKey)
fmt.Printf("Chain Code: %x\n", resp.ChainCode)
```

---

## How to Run

### Prerequisites

- Go 1.18 or later installed on your system.

### Steps

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd awesomeProject
   ```

2. Run the tests:
   ```bash
   go test ./...
   ```

3. Run the example in `main.go`:
   ```bash
   go run main.go
   ```

---

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.