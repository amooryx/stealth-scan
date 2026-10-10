<div align="center">
  <img src="./banner.svg" alt="stealth-scan" width="800">
</div>

# stealth-scan

`stealth-scan` is a bounded TCP connect inventory utility for assets you are
authorized to assess. It scans one explicitly supplied IP address; the
operator must also declare the authorized CIDR containing it. It does not
resolve hostnames or iterate through the rest of a network.

## Requirements

- Python 3.10 or newer
- No third-party packages (standard library only)

Run the offline tests with:

```bash
python -m unittest discover -s tests -v
```

## Usage

For a local-only check:

```bash
python stealth_scan.py 127.0.0.1 --scope 127.0.0.1/32 --ports 22,80,443
```

The tool prompts for authorization unless `--yes` is supplied. `--yes` only
skips that prompt; it does not replace the required `--scope` declaration.
Use `--help` for all options. For example, `--workers` is limited to 1-32
(default 16), each connection timeout is limited to 0.1-3 seconds (default
1.2), and a custom `--ports` list is limited to 128 unique ports. The built-in
port set contains 32 common TCP ports. At most 64 bytes are read for a banner
from each open port. `-o results.json` writes structured results.

## Implemented behavior

- TCP connect checks for one IPv4 or IPv6 literal target within a declared
  IPv4/IPv6 CIDR scope.
- A curated default TCP port set or a validated custom port list.
- Bounded parallel connections and per-connection/banner read timeouts.
- Optional capture of a short, unsolicited service banner.
- JSON results containing observed open ports and informational findings.
  An open listener is an observation, not by itself a vulnerability or risk
  rating.

## Limitations

- This is not a stealth or evasion tool. It makes ordinary TCP connection
  attempts and may be visible to the target and network monitors.
- It does not scan all addresses in `--scope`, scan UDP, identify operating
  systems, authenticate, test vulnerabilities, or execute payloads.
- Service labels are port-based guesses; banners may be absent or misleading.
- Results are limited to the selected ports and the target's state at scan
  time. A closed or unobserved port does not establish that a service is
  permanently unavailable.

Use only within the scope you are authorized to assess.

**Omar Khalid** — [omareldemery.com](https://omareldemery.com)
