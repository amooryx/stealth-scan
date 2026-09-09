import socket, concurrent.futures as cf, rclib

TOP = [21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1433,1521,2049,
       3128,3306,3389,5432,5900,5985,5986,6379,8000,8080,8443,8888,9200,27017]
NAMES = {21:"ftp",22:"ssh",23:"telnet",25:"smtp",53:"dns",80:"http",110:"pop3",
         135:"msrpc",139:"netbios",143:"imap",443:"https",445:"smb",1433:"mssql",
         3306:"mysql",3389:"rdp",5432:"postgres",5985:"winrm",5986:"winrm-tls",
         6379:"redis",8080:"http-alt",8443:"https-alt",9200:"elastic",27017:"mongodb"}

def probe(host, port):
    s = socket.socket(); s.settimeout(1.2)
    try:
        if s.connect_ex((host, port)) == 0:
            banner = ""
            try: s.settimeout(0.6); banner = s.recv(64).decode("latin1").strip()
            except OSError: pass
            return port, banner
    except OSError: pass
    finally: s.close()
    return None

def run(ctx):
    host = ctx.target
    ports = TOP
    if getattr(ctx.args, "ports", None):
        ports = [int(p) for p in ctx.args.ports.split(",") if p.strip().isdigit()]
    ctx.info(f"TCP connect scan · {len(ports)} ports")
    openp = []
    with cf.ThreadPoolExecutor(max_workers=100) as ex:
        for r in ex.map(lambda p: probe(host, p), ports):
            if r:
                port, banner = r; openp.append(port)
                svc = NAMES.get(port, "?")
                ctx.good(f"{port:>5}/tcp  open  {svc}" + (f"  {banner[:40]}" if banner else ""))
                sev = "high" if port in (3389,445,6379,9200,27017,5985) else "info"
                ctx.finding(f"open port {port} ({svc})", sev, evidence={"banner": banner})
    ctx.data["open_ports"] = openp
    if not openp: ctx.warn("no open ports in set")
    return 0

def args(p): p.add_argument("--ports", help="comma list, e.g. 80,443,8080")
rclib.main("stealth-scan", "Low-noise TCP connect scan with banners", run, extra_args=args)
