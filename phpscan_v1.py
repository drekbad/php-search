#!/usr/bin/env python3
"""
php2shell_inventory.py -- IDENTIFICATION ONLY (no payloads, no exploitation).

Finds PHP that may be exposed to PHP2Shell (CVE-2026-109618 / CVE-2026-109619)
and flags the session.upload_progress condition tied to CVE-2026-115560.

  net    plain GET / and /index.php, fingerprint X-Powered-By / Server / PHPSESSID
         python3 php2shell_inventory.py net -t targets.txt [-p 80,443,8080,8443] [-o php_net.csv]

  local  run on each host (root recommended): PHP binaries + SAPIs, packages,
         distro backport evidence, effective ini settings, workers still running
         pre-patch code, optional container check
         sudo python3 php2shell_inventory.py local [--containers] [--json out.json]

Upstream fixed: 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35. 5.4-8.1 = EOL (no upstream fix for -109618).
Stdlib only, Python 3.6+.
"""
import argparse, concurrent.futures as cf, csv, glob, gzip, http.client, ipaddress, json, os, re, shutil, socket, ssl, subprocess, sys

FIXED = {(8, 5): 12, (8, 4): 27, (8, 3): 36, (8, 2): 35}
VER_RE = re.compile(r'PHP[/ ]v?(\d+)\.(\d+)\.(\d+)([^\s;,()]*)', re.I)
CVE_RE = re.compile(r'CVE-2026-10961[89]')
BACKPORT_RE = re.compile(r'deb|ubuntu|el\d|amzn|suse|alpine|\+', re.I)


def classify(maj, mi, pa, suffix=""):
    k = (maj, mi)
    if k in FIXED:
        st = "FIXED" if pa >= FIXED[k] else "VULNERABLE"
    elif k < (8, 2):
        st = "VULNERABLE_EOL"
    else:
        st = "FIXED"  # newer branch than tracked
    if st != "FIXED" and BACKPORT_RE.search(suffix or ""):
        st += " (distro build - verify backport)"
    return st


def parse_ver(text):
    m = VER_RE.search(text or "")
    if not m:
        return None, None, None
    return "%s.%s.%s%s" % (m[1], m[2], m[3], m[4]), classify(int(m[1]), int(m[2]), int(m[3]), m[4]), "%s.%s" % (m[1], m[2])


# --------------------------------------------------------------------- network
UA = {"User-Agent": "php2shell-inventory/1.0 (authorized asset identification)", "Connection": "close"}


def expand(lines):
    for t in lines:
        t = t.split("#")[0].strip()
        if not t:
            continue
        try:
            n = ipaddress.ip_network(t, strict=False)
            yield from (map(str, n.hosts()) if n.num_addresses > 2 else map(str, n))
        except ValueError:
            yield t  # hostname / FQDN (preferred: hits the right vhost)


def get(host, port, path, tls, to):
    if tls:
        c = http.client.HTTPSConnection(host, port, timeout=to, context=ssl._create_unverified_context())
    else:
        c = http.client.HTTPConnection(host, port, timeout=to)
    try:
        c.request("GET", path, headers=UA)
        r = c.getresponse()
        return r.status, r.getheaders()
    finally:
        c.close()


def analyze(host, port, scheme, resps):
    xpb = server = ""
    sess = False
    for _, hdrs in resps:
        for k, v in hdrs:
            k = k.lower()
            if k == "x-powered-by" and not xpb:
                xpb = v
            elif k == "server" and not server:
                server = v
            elif k == "set-cookie" and v.upper().startswith("PHPSESSID="):
                sess = True
    ver, st, _ = parse_ver(xpb) if "php" in xpb.lower() else (None, None, None)
    if not ver:
        ver, st, _ = parse_ver(server)
    if ver:
        ind = "PHP version banner"
    elif "php" in (xpb + server).lower() or sess:
        ind, st = "PHP present, no version (expose_php=Off) - verify locally", "UNKNOWN"
    else:
        ind = "no PHP fingerprint"
    return dict(host=host, port=port, scheme=scheme, php_version=ver or "", status=st or "",
                indicator=ind, x_powered_by=xpb, server=server, phpsessid=sess)


def probe(host, port, paths, to):
    try:
        socket.create_connection((host, port), timeout=to).close()
    except OSError:
        return None
    for tls in (True, False):
        try:
            resps = [get(host, port, paths[0], tls, to)]
        except Exception:
            continue
        for p in paths[1:]:
            try:
                resps.append(get(host, port, p, tls, to))
            except Exception:
                pass
        return analyze(host, port, "https" if tls else "http", resps)
    return dict(host=host, port=port, indicator="open, no HTTP response")


def net_main(a):
    with open(a.targets) as fh:
        targets = list(expand(fh))
    ports = [int(p) for p in a.ports.split(",")]
    fields = ["host", "port", "scheme", "php_version", "status", "indicator", "x_powered_by", "server", "phpsessid"]
    rows = []
    with cf.ThreadPoolExecutor(a.workers) as ex:
        futs = [ex.submit(probe, h, p, ["/", "/index.php"], a.timeout) for h in targets for p in ports]
        for f in cf.as_completed(futs):
            r = f.result()
            if r and (a.all or r.get("status")):
                rows.append(r)
                if r.get("status"):
                    print("%-40s %-5s %-14s %s" % ("%s:%s" % (r["host"], r["port"]), r.get("scheme", ""), r["php_version"] or "-", r["status"]))
    rows.sort(key=lambda r: (r["host"], r["port"]))
    with open(a.out, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, restval="")
        w.writeheader()
        w.writerows(rows)
    php = [r for r in rows if r.get("status")]
    print("\n%d PHP endpoints | %d VULNERABLE* | %d UNKNOWN version -> %s"
          % (len(php), sum(r["status"].startswith("VULN") for r in php), sum(r["status"] == "UNKNOWN" for r in php), a.out))
    print("Banner absence != no PHP. Treat 'local' mode as source of truth.")


# ----------------------------------------------------------------------- local
BIN_GLOBS = [
    "/usr/bin/php*", "/usr/sbin/php-fpm*", "/usr/lib/cgi-bin/php*", "/usr/local/bin/php*", "/usr/local/sbin/php-fpm*",
    "/opt/remi/php*/root/usr/bin/php", "/opt/remi/php*/root/usr/sbin/php-fpm",
    "/opt/cpanel/ea-php*/root/usr/bin/php", "/opt/cpanel/ea-php*/root/usr/sbin/php-fpm",
    "/opt/plesk/php/*/bin/php", "/opt/plesk/php/*/sbin/php-fpm",
    "/usr/local/lsws/lsphp*/bin/lsphp", "/opt/bitnami/php/bin/php", "/opt/bitnami/php/sbin/php-fpm",
    "/usr/local/php*/bin/php", "/usr/local/php*/sbin/php-fpm",
    "/usr/bin/frankenphp", "/usr/local/bin/frankenphp",
]
SKIP = ("config", "ize", "phar", "dbg", "unit")
CFG_GLOBS = [
    "/etc/php.ini", "/etc/php.d/*.ini", "/etc/php-fpm.conf", "/etc/php-fpm.d/*.conf",
    "/etc/php/*/*/php.ini", "/etc/php/*/*/conf.d/*.ini", "/etc/php/*/fpm/pool.d/*.conf",
    "/etc/opt/remi/php*/php.ini", "/etc/opt/remi/php*/php.d/*.ini", "/etc/opt/remi/php*/php-fpm.d/*.conf",
    "/opt/cpanel/ea-php*/root/etc/php.ini", "/opt/cpanel/ea-php*/root/etc/php.d/*.ini", "/opt/cpanel/ea-php*/root/etc/php-fpm.d/*.conf",
    "/usr/local/etc/php/php.ini", "/usr/local/etc/php/conf.d/*.ini", "/usr/local/etc/php-fpm.d/*.conf", "/usr/local/lib/php.ini",
    "/usr/local/lsws/lsphp*/etc/php/*/litespeed/php.ini",
    "/etc/apache2/**/*.conf", "/etc/httpd/**/*.conf",
]
CFG_RE = re.compile(r'(session\.upload_progress\.enabled|fatal_error_backtraces)\s*\]?\s*=?\s*"?(\w+)', re.I)
INI_KEYS = ("Server API", "Loaded Configuration File", "session.upload_progress.enabled", "fatal_error_backtraces")


def run(cmd, to=20):
    try:
        return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True, timeout=to).stdout
    except Exception:
        return ""


def phpinfo_fields(raw):
    # handles CLI/FPM text output and php-cgi HTML output
    txt = re.sub(r'</td>\s*<td[^>]*>', " => ", raw)
    txt = re.sub(r'<[^>]+>', "\n", txt)
    out = {}
    for line in txt.splitlines():
        line = line.strip()
        for k in INI_KEYS:
            if line.startswith(k + " =>"):
                out.setdefault(k, line.split(" => ")[1].strip())
    return out


def on(v):
    return str(v).strip().lower() not in ("off", "0", "false", "no", "", "none")


def local_main(a):
    rep = {"host": socket.getfqdn(), "binaries": [], "config": [], "packages": [], "backport_evidence": [], "workers": [], "containers": []}

    # packages + backport evidence (distros patch without bumping upstream version; RHEL often shows no suffix)
    if shutil.which("dpkg-query"):
        for l in run(["dpkg-query", "-W", "-f=${db:Status-Abbrev} ${Package} ${Version}\n"]).splitlines():
            p = l.split()
            if len(p) == 3 and p[0].startswith("ii") and re.match(r'(php|libapache2-mod-php)', p[1]):
                rep["packages"].append(p[1] + " " + p[2])
        for f in glob.glob("/usr/share/doc/*php*/changelog.Debian.gz"):
            try:
                with gzip.open(f, "rt", errors="ignore") as fh:
                    if CVE_RE.search(fh.read()):
                        rep["backport_evidence"].append(f)
            except OSError:
                pass
    if shutil.which("rpm"):
        for l in run(["rpm", "-qa", "--qf", "%{NAME} %{VERSION}-%{RELEASE}\n"]).splitlines():
            if re.match(r'(ea-)?php', l):
                rep["packages"].append(l)
                name = l.split()[0]
                if re.search(r'(common|cli)$', name) and CVE_RE.search(run(["rpm", "-q", "--changelog", name])):
                    rep["backport_evidence"].append(l)
    if shutil.which("apk"):
        rep["packages"] += [l for l in run(["apk", "info", "-v"]).splitlines() if l.startswith("php")]

    # binaries
    cands = set()
    for g in BIN_GLOBS:
        cands.update(glob.glob(g))
    for n in ("php", "php-fpm", "php-cgi", "lsphp", "frankenphp"):
        if shutil.which(n):
            cands.add(shutil.which(n))
    seen = set()
    for b in sorted(cands):
        real = os.path.realpath(b)
        name = os.path.basename(real)
        if real in seen or os.path.isdir(real) or not os.access(real, os.X_OK) or any(s in name for s in SKIP):
            continue
        seen.add(real)
        fr = "frankenphp" in name
        out = run([real, "version"] if fr else [real, "-v"])
        ver, st, mm = parse_ver(out)
        if not ver:
            continue
        info = {"path": b, "version": ver, "status": st}
        if st != "FIXED" and any(mm in e or mm.replace(".", "") in e for e in rep["backport_evidence"]):
            info["status"] = "LIKELY_FIXED (distro changelog references CVE)"
        if not fr:
            info.update(phpinfo_fields(run([real, "-i"])))
        rep["binaries"].append(info)

    # config files (per-SAPI ini can differ from CLI; pools/vhosts can override)
    for g in CFG_GLOBS:
        for f in glob.glob(g, recursive=True):
            try:
                with open(f, errors="ignore") as fh:
                    for i, line in enumerate(fh, 1):
                        s = line.strip()
                        if s.startswith((";", "#")):
                            continue
                        m = CFG_RE.search(s)
                        if m:
                            rep["config"].append({"file": f, "line": i, "setting": m[1], "value": m[2]})
            except OSError:
                pass

    # running workers: binary / libphp replaced on disk since start => still running pre-patch code
    agg = {}
    for pid in filter(str.isdigit, os.listdir("/proc")):
        try:
            exe = os.readlink("/proc/%s/exe" % pid)
        except OSError:
            continue
        base = os.path.basename(exe.replace(" (deleted)", ""))
        if base in ("apache2", "httpd"):
            try:
                with open("/proc/%s/maps" % pid) as fh:
                    m = re.search(r'(\S*libphp\S*\.so)( \(deleted\))?', fh.read())
            except OSError:
                m = None
            if not m:
                continue
            key, stale = "mod_php: " + m[1], bool(m[2])
        elif re.search(r'php|lsphp|frankenphp', base):
            key, stale = exe.replace(" (deleted)", ""), exe.endswith("(deleted)")
        else:
            continue
        d = agg.setdefault(key, {"target": key, "procs": 0, "stale_procs": 0})
        d["procs"] += 1
        d["stale_procs"] += stale
    rep["workers"] = list(agg.values())

    # containers (opt-in)
    if a.containers and shutil.which("docker"):
        for l in run(["docker", "ps", "--format", "{{.ID}} {{.Image}}"]).splitlines():
            cid, img = l.split(" ", 1)
            out = run(["docker", "exec", cid, "sh", "-c", "php -v 2>/dev/null || php-fpm -v 2>/dev/null || frankenphp version 2>/dev/null"])
            ver, st, _ = parse_ver(out)
            if ver:
                rep["containers"].append({"id": cid, "image": img, "version": ver, "status": st})

    # ---- verdict
    flags, sev = [], 0
    print("== %s ==" % rep["host"])
    for b in rep["binaries"]:
        upl = b.get("session.upload_progress.enabled", "?")
        print("  %-45s %-22s %-14s %s  upload_progress=%s" % (b["path"], b["version"], b.get("Server API", "-")[:14], b["status"], upl))
        if b["status"].startswith("VULN"):
            sev = max(sev, 2)
        if on(upl) and upl != "?":
            flags.append("%s: session.upload_progress.enabled=On (CVE-2026-115560 condition)" % b["path"])
    for c in rep["config"]:
        if c["setting"].lower().startswith("session") and on(c["value"]):
            flags.append("%s:%d sets upload_progress On" % (c["file"], c["line"]))
    for w in rep["workers"]:
        print("  worker %-50s procs=%d stale=%d" % (w["target"], w["procs"], w["stale_procs"]))
        if w["stale_procs"]:
            sev = max(sev, 2)
            flags.append("%s: %d process(es) running replaced binary/lib -> restart" % (w["target"], w["stale_procs"]))
    for c in rep["containers"]:
        print("  container %s %-30s %-16s %s" % (c["id"], c["image"][:30], c["version"], c["status"]))
        if c["status"].startswith("VULN"):
            sev = max(sev, 2)
    if rep["backport_evidence"]:
        print("  backport evidence: " + ", ".join(rep["backport_evidence"]))
    if not rep["binaries"] and not rep["workers"]:
        print("  no PHP found in known locations (not proof of absence)")
    for f in flags:
        print("  [!] " + f)
        sev = max(sev, 1)
    if a.json:
        with open(a.json, "w") as fh:
            json.dump(rep, fh, indent=2)
    return sev  # 0 clean, 1 config flags, 2 vulnerable/stale


def main():
    ap = argparse.ArgumentParser(description="PHP2Shell exposure identification (no exploitation)")
    sp = ap.add_subparsers(dest="mode")
    n = sp.add_parser("net")
    n.add_argument("-t", "--targets", required=True, help="file: IPs, CIDRs, hostnames (one per line)")
    n.add_argument("-p", "--ports", default="80,443,8080,8443")
    n.add_argument("-o", "--out", default="php_net.csv")
    n.add_argument("-w", "--workers", type=int, default=64)
    n.add_argument("--timeout", type=float, default=4)
    n.add_argument("--all", action="store_true", help="include non-PHP responders in CSV")
    l = sp.add_parser("local")
    l.add_argument("--containers", action="store_true", help="docker exec into running containers to read PHP version")
    l.add_argument("--json")
    a = ap.parse_args()
    if a.mode == "net":
        net_main(a)
    elif a.mode == "local":
        sys.exit(local_main(a))
    else:
        ap.print_help()


if __name__ == "__main__":
    main()
