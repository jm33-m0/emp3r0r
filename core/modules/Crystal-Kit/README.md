# Crystal Kit

This repo is a technical and social experiment to explore whether replacing Cobalt Strike's evasion primitives (Sleepmask/BeaconGate) with a [Crystal Palace](https://tradecraftgarden.org/) PICO is feasible (or even desirable) for advanced evasion scenarios.

## Usage

1. Disable the sleepmask and stage obfuscations in Malleable C2.

```text
stage {
    set sleep_mask "false";
    set cleanup "true";
    transform-obfuscate { }
}

post-ex {
    set cleanup "true";
    set smartinject "true";
}
```

2. Copy `crystalpalace.jar` to your Cobalt Strike client directory.
3. Load `crystalkit.cna`.  

### Notes

- Tested on Cobalt Strike 4.12.
- Can work with any post-ex DLL capability.
