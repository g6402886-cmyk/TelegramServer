# TelegramServer

Telegram-compatible server foundation for a forked Android Telegram client.

This repository starts with a small Go MTProto TCP gateway. The first milestone is to make the client connect to this server, complete MTProto authorization-key creation, and then serve a minimal API surface (`help.getConfig`, `auth.sendCode`, `auth.signIn`).

## Current status

Implemented:

- TCP listener entrypoint.
- MTProto obfuscated transport detection for abridged, intermediate, and padded intermediate modes.
- Basic unencrypted MTProto envelope parsing.
- `req_pq` / `req_pq_multi` detection.
- `resPQ` response encoding with the configured RSA key fingerprint.
- `req_DH_params` parsing, RSA decrypt, AES-IGE encrypted `server_DH_inner_data`, and DH `g_a` generation.
- `set_client_DH_params` parsing and auth-key derivation.

Not implemented yet:

- Encrypted message containers and API RPC handlers.
- Persistent users, sessions, chats, and updates.

## RSA key

Generate a development RSA keypair before running:

```bash
openssl genrsa 2048 > server_rsa_private.pem
openssl rsa -in server_rsa_private.pem -RSAPublicKey_out -out server_rsa_public.pem
```

Do not commit `server_rsa_private.pem`. Patch the Android client with `server_rsa_public.pem` and the fingerprint logged by the server on startup.

## Run

```bash
go run ./cmd/telegramserver -addr :10443 -rsa-key server_rsa_private.pem
```

Port `10443` does not require root. You can choose another port if needed:

```bash
go run ./cmd/telegramserver -addr :15443 -rsa-key server_rsa_private.pem
```

## Test

```bash
go test ./...
```

## Roadmap

1. Finish MTProto auth-key handshake:
   - `req_pq_multi`
   - `req_DH_params`
   - `set_client_DH_params`
2. Add encrypted message parsing.
3. Add minimal RPC methods:
   - `help.getConfig`
   - `auth.sendCode`
   - `auth.signIn`
4. Patch Android client datacenters to use this server.
5. Add users, dialogs, messages, media, and updates.
