# TelegramServer

Telegram-compatible server foundation for a forked Android Telegram client.

This repository starts with a small Go MTProto TCP gateway. The first milestone is to make the client connect to this server, complete MTProto authorization-key creation, and then serve a minimal API surface (`help.getConfig`, `auth.sendCode`, `auth.signIn`).

## Current status

Implemented:

- TCP listener entrypoint.
- MTProto obfuscated transport detection for abridged, intermediate, and padded intermediate modes.
- Basic unencrypted MTProto envelope parsing.
- `req_pq` / `req_pq_multi` detection.
- `resPQ` response encoding with Telegram test public key fingerprint placeholder.

Not implemented yet:

- RSA private-key decrypt for `req_DH_params`.
- AES-IGE encrypted `server_DH_inner_data`.
- Diffie-Hellman auth-key derivation.
- Encrypted message containers and API RPC handlers.
- Persistent users, sessions, chats, and updates.

## Run

```bash
go run ./cmd/telegramserver -addr :10443
```

Port `10443` does not require root. You can choose another port if needed:

```bash
go run ./cmd/telegramserver -addr :15443
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
