# Android client connection notes

The Android client currently connects to official Telegram datacenters from:

```text
TMessagesProj/jni/tgnet/ConnectionsManager.cpp
```

For the first local server test, replace DC1 addresses in `ConnectionsManager::initDatacenters()` with the custom server address and temporarily remove the other production DC entries:

```cpp
datacenter = new Datacenter(instanceNum, 1);
datacenter->addAddressAndPort("10.0.2.2", 10443, 0, "");
datacenters[1] = datacenter;
```

Use:

- `10.0.2.2` for Android emulator reaching the host machine.
- LAN/public server IP for a physical device.
- Port `10443` by default, or whichever `-addr` port the Go server listens on.

The client also contains built-in server public key fingerprints in `Handshake.cpp`.

Generate a server keypair:

```bash
openssl genrsa 2048 > server_rsa_private.pem
openssl rsa -in server_rsa_private.pem -RSAPublicKey_out -out server_rsa_public.pem
```

Start the server once and copy the logged fingerprint:

```bash
go run ./cmd/telegramserver -addr :10443 -rsa-key server_rsa_private.pem
```

Then patch `TMessagesProj/jni/tgnet/Handshake.cpp`:

1. Add the contents of `server_rsa_public.pem` to `serverPublicKeys`.
2. Add the logged fingerprint to `serverPublicKeysFingerprints`.
3. Rebuild the Android client.

Do not commit `server_rsa_private.pem`.
