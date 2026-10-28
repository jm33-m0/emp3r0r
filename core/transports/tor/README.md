# Tor custom transport

Reference implementation of a custom C2 transport: an agent dialer and a
bridge for a Tor hidden service. The Go dialer is in this directory; the C
provider is `core/c_agent/src/transport/transport_tor.c`.

See [Custom C2 transports](../../../docs/CUSTOM_C2.md) for setup, options,
and how to write your own transport.
