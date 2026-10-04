# Optional Local Ghidra Bridge

## Overview

`ghidra_bridge.py` is an optional local helper for the Homunculus Threat Feed.

The core threat feed works without Ghidra or this bridge. The bridge exists only for users
who want the Discord investigation link to acquire a payload into a local analysis directory
and open a local Ghidra project after acquisition succeeds.

The bridge listens only on:

```text
127.0.0.1:9999
```

It is not intended to be exposed to a local network or the public internet.

## What the Discord link does

A Discord alert may include a link labelled similar to:

```text
Acquire & Open in Local Ghidra
```

The link points to a local URL such as:

```text
http://127.0.0.1:9999/triage?target=...
```

`127.0.0.1` always refers to the computer where the link is opened.

This means:

- The bridge works only on a computer where `ghidra_bridge.py` is running.
- Ghidra must be installed on that same computer.
- Other Discord users do not use another person's bridge.
- If the bridge is not installed, the link can be ignored.
- The threat feed itself continues to work normally without the bridge.

## Acquisition workflow

When a user opens the local bridge link, the bridge:

1. Checks that the local Ghidra executable is available.
2. Receives the target URL from the local browser.
3. Refangs `hxxp`, `hxxps`, and `[.]` notation when required.
4. Downloads to a temporary `.part` file in `samples/`.
5. Uses bounded timeouts, retry attempts, per-target locking, and safe HTTP Range resume
   when the source server supports HTTP `206 Partial Content`.
6. Verifies the complete byte count when the server provides one.
7. Atomically renames the `.part` file to the final filename only after a complete download.
8. Opens Ghidra and the local samples directory only after successful acquisition.

The bridge does not execute downloaded files.

## Important limitation

A reachable host is not a guarantee that a payload can be downloaded.

Malware-hosting infrastructure may:

- Return HTTP headers but never send a response body.
- Send only part of a file and then stall.
- Remove a payload after it appears in a threat feed.
- Block selected IP addresses, networks, regions, or user agents.
- Ignore HTTP Range requests.
- Return an HTML block page, archive, script, or different content instead of the expected payload.
- Close connections unpredictably.

The bridge reports acquisition failures and does not open Ghidra for incomplete downloads.
A retained `.part` file is incomplete and must not be treated as a complete sample.

## Manual use of defanged links

Threat alerts show URLs in defanged form, for example:

```text
hxxp://example[.]invalid/path
```

Users may refang these links manually at their own discretion:

```text
http://example.invalid/path
```

Only do this from a dedicated, isolated malware-analysis environment. Refanging and visiting
or retrieving a malicious URL can expose the analysis environment to hostile infrastructure.

Do not paste live malicious links into a normal daily-use workstation, browser profile, or
production network.

## Requirements

- Linux desktop session with a local graphical environment.
- Python 3.
- Ghidra installed locally.
- `file`, `notify-send`, and `xdg-open` available on the local system.
- A dedicated analysis VM or similarly isolated environment is strongly recommended.
- The repository directory should be writable so the bridge can create `samples/`.

## Install as a user service

The service file assumes this repository is cloned at:

```text
~/homunculus-threat-feed
```

If it is stored elsewhere, edit `WorkingDirectory` and `ExecStart` in
`systemd/ghidra-bridge.service` before installing.

Install and start the optional user service:

```bash
mkdir -p ~/.config/systemd/user
cp systemd/ghidra-bridge.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now ghidra-bridge.service
```

Check service status:

```bash
systemctl --user status ghidra-bridge.service --no-pager
```

Watch bridge logs while testing:

```bash
journalctl --user -u ghidra-bridge.service -f
```

Stop and disable the bridge:

```bash
systemctl --user disable --now ghidra-bridge.service
```

## Download outcomes

A successful acquisition produces a completed local file in:

```text
samples/
```

An incomplete acquisition remains as:

```text
samples/<filename>.part
```

Do not import `.part` files into Ghidra as normal samples.

Before importing a completed file, identify it without executing it:

```bash
file samples/<filename>
```

If it is an archive, validate it before extracting or importing:

```bash
unzip -t samples/<filename>
```

File extensions are not trustworthy. A name ending in `.sh`, `.zip`, `.bin`, or `.exe` is not
proof of the file's actual format.

## Security model

The bridge binds exclusively to loopback address `127.0.0.1`.

Do not change it to `0.0.0.0` or expose port `9999` through firewall rules, port forwarding,
reverse proxies, tunnels, or public hosting.

The bridge downloads untrusted content. Use it only where local acquisition of potentially
malicious samples is intentional, authorized, and isolated from personal or production data.
