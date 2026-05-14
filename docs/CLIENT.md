# Android client connection notes

The Android client currently connects to official Telegram datacenters from:

```text
TMessagesProj/jni/tgnet/ConnectionsManager.cpp
```

For the first local server test, replace DC1 addresses in `ConnectionsManager::initDatacenters()` with the custom server address:

```cpp
datacenter = new Datacenter(instanceNum, 1);
datacenter->addAddressAndPort("10.0.2.2", 10443, 0, "");
datacenters[1] = datacenter;
```

Use:

- `10.0.2.2` for Android emulator reaching the host machine.
- LAN/public server IP for a physical device.
- Port `10443` by default, or whichever `-addr` port the Go server listens on.

The client also contains built-in server public key fingerprints in `Handshake.cpp`. A fully custom production server should add its own RSA public key/fingerprint there or make the key configurable. For the current bootstrap, the server advertises the Telegram production fingerprint placeholder so the client can progress to the next handshake phase while the custom key path is implemented.
