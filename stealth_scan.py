import argparse
import concurrent.futures as cf
import ipaddress
import socket

import rclib

TOP = (
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1433, 1521, 2049, 3128, 3306, 3389, 5432, 5900, 5985, 5986, 6379,
    8000, 8080, 8443, 8888, 9200, 27017,
)
MAX_PORTS = 128
MAX_WORKERS = 32
MIN_TIMEOUT = 0.1
MAX_TIMEOUT = 3.0
MAX_BANNER_BYTES = 64

NAMES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios", 143: "imap",
    443: "https", 445: "smb", 993: "imaps", 995: "pop3s", 1433: "mssql",
    1521: "oracle", 2049: "nfs", 3128: "http-proxy", 3306: "mysql",
    3389: "rdp", 5432: "postgres", 5900: "vnc", 5985: "winrm",
    5986: "winrm-tls", 6379: "redis", 8000: "http-alt", 8080: "http-alt",
    8443: "https-alt", 8888: "http-alt", 9200: "elastic", 27017: "mongodb",
}


def parse_ports(value):
    """Parse a non-empty, bounded comma-separated TCP port list."""
    parts = value.split(",")
    if not parts or any(not part.strip().isdigit() for part in parts):
        raise argparse.ArgumentTypeError("ports must be comma-separated integers")
    ports = [int(part.strip()) for part in parts]
    if any(port < 1 or port > 65535 for port in ports):
        raise argparse.ArgumentTypeError("ports must be in the range 1-65535")
    if len(set(ports)) != len(ports):
        raise argparse.ArgumentTypeError("ports must not contain duplicates")
    if len(ports) > MAX_PORTS:
        raise argparse.ArgumentTypeError(f"no more than {MAX_PORTS} ports may be scanned")
    return ports


def parse_workers(value):
    try:
        workers = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("workers must be an integer") from exc
    if not 1 <= workers <= MAX_WORKERS:
        raise argparse.ArgumentTypeError(f"workers must be in the range 1-{MAX_WORKERS}")
    return workers


def parse_timeout(value):
    try:
        timeout = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("timeout must be a number of seconds") from exc
    if not MIN_TIMEOUT <= timeout <= MAX_TIMEOUT:
        raise argparse.ArgumentTypeError(
            f"timeout must be in the range {MIN_TIMEOUT}-{MAX_TIMEOUT} seconds"
        )
    return timeout


def validate_scope(target, scope):
    """Require an IP-literal target contained by the operator-declared network."""
    try:
        address = ipaddress.ip_address(target)
    except ValueError as exc:
        raise ValueError("target must be an IPv4 or IPv6 address literal (DNS names are not resolved)") from exc
    try:
        network = ipaddress.ip_network(scope, strict=False)
    except ValueError as exc:
        raise ValueError("scope must be a valid IPv4 or IPv6 CIDR network") from exc
    if address.version != network.version or address not in network:
        raise ValueError(f"target {address} is outside declared scope {network}")
    return str(address)


def probe(host, port, timeout):
    address = ipaddress.ip_address(host)
    family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sockaddr = (str(address), port, 0, 0) if address.version == 6 else (str(address), port)
        if sock.connect_ex(sockaddr) != 0:
            return None
        banner = ""
        try:
            sock.settimeout(min(timeout, 0.6))
            banner = sock.recv(MAX_BANNER_BYTES).decode("latin1").strip()
        except OSError:
            pass
        return port, banner
    except OSError:
        return None
    finally:
        sock.close()


def run(ctx):
    host = validate_scope(ctx.target, ctx.args.scope)
    ports = ctx.args.ports if ctx.args.ports is not None else TOP
    ctx.info(f"TCP connect inventory · {len(ports)} ports · {ctx.args.max_workers} workers")
    openp = []
    with cf.ThreadPoolExecutor(max_workers=ctx.args.max_workers) as executor:
        results = executor.map(lambda port: probe(host, port, ctx.args.timeout), ports)
        for result in results:
            if result:
                port, banner = result
                openp.append(port)
                service = NAMES.get(port, "unknown")
                ctx.good(f"{port:>5}/tcp  open  {service}" + (f"  {banner[:MAX_BANNER_BYTES]}" if banner else ""))
                ctx.finding(
                    f"open TCP port {port} ({service})",
                    "info",
                    detail="listener observed; exposure risk was not assessed",
                    evidence={"banner": banner},
                )
    ctx.data["open_ports"] = openp
    if not openp:
        ctx.warn("no open ports in the selected set")
    return 0


def args(parser):
    parser.add_argument(
        "--scope",
        required=True,
        help="authorized IPv4/IPv6 CIDR containing the single target (required)",
    )
    parser.add_argument(
        "--ports",
        type=parse_ports,
        help=f"comma-separated TCP ports (1-65535; maximum {MAX_PORTS})",
    )
    parser.add_argument(
        "--workers",
        dest="max_workers",
        type=parse_workers,
        default=16,
        help=f"parallel TCP connections (1-{MAX_WORKERS}; default: 16)",
    )
    parser.add_argument(
        "--timeout",
        type=parse_timeout,
        default=1.2,
        help=f"per-connection timeout in seconds ({MIN_TIMEOUT}-{MAX_TIMEOUT}; default: 1.2)",
    )


def main():
    return rclib.main(
        "stealth-scan",
        "Bounded TCP connect inventory for an explicitly authorized IP scope",
        run,
        extra_args=args,
        target_help="single IPv4/IPv6 address inside --scope",
    )


if __name__ == "__main__":
    raise SystemExit(main())
