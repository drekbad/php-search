#!/usr/bin/env python3
"""
php2shell_inventory.py -- IDENTIFICATION ONLY (no payloads, no exploitation).

Finds PHP that may be exposed to PHP2Shell (CVE-2026-109618 / CVE-2026-109619)
and flags the session.upload_progress condition tied to CVE-2026-115560.

  net    plain GET / and /index.php, fingerprint X-Powered-By / Server / PHPSESSID
         python3 php2shell_inventory.py net -t targets.txt [-p 80,443,8080,8443] [-o php_net.csv] [-w 256] [--resume]
         live progress on stderr, hits on stdout, CSV written incrementally, Ctrl-C safe

  local  run on each host (root recommended): PHP binaries + SAPIs, packages,
         distro backport evidence, effective ini settings, workers still running
         pre-patch code, optional container check
         sudo python3 php2shell_inventory.py local [--containers] [--json out.json]

Upstream fixed: 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35. 5.4-8.1 = EOL (no upstream fix for -109618).
Stdlib only, Python 3.6+.
"""
import argparse, concurrent.futures as cf, csv, glob, gzip, http.client, ipaddress, json, os, re, shutil, socket, ssl, subprocess, sys, time

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
UA = {"User-Agent": "php2shell-inventory/1.1 (authorized asset identification)", "Connection": "close"}
CTX = ssl._create_unverified_context()
TLS_PORTS = {443, 8443, 9443, 4443, 10443, 2083, 2087, 2096}
FIELDS = ["host", "port", "scheme", "php_version", "status", "indicator", "x_powered_by", "server", "phpsessid"]
SILENT = "TCP open, no response (likely FW proxy)"


class ConnectFail(Exception):
    pass


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


def is_ip(h):
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False


def http_get(host, port, path, tls, cto, rto):
    try:
        s = socket.create_connection((host, port), timeout=cto)
    except OSError as e:
        raise ConnectFail(e)
    try:
        if tls:  # handshake bounded by connect timeout
            s = CTX.wrap_socket(s, server_hostname=None if is_ip(host) else host)
        s.settimeout(rto)
        c = http.client.HTTPConnection(host, port)
        c.sock = s
        c.request("GET", path, headers=UA)
        r = c.getresponse()
        return r.status, r.getheaders()
    finally:
        s.close()


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


def probe(host, port, cto, rto):
    tls_first = port in TLS_PORTS or str(port).endswith("443")
    timed_out = False
    for i, tls in enumerate((tls_first, not tls_first)):
        try:
            # 2nd scheme gets a short window: a real server rejects the wrong protocol fast,
            # a firewall answering on a host's behalf never sends anything
            first = http_get(host, port, "/", tls, cto, rto if i == 0 else cto)
        except ConnectFail:
            return None
        except socket.timeout:
            timed_out = True
            continue
        except Exception:
            continue
        resps = [first]
        row = analyze(host, port, "https" if tls else "http", resps)
        if not row["status"]:
            try:
                resps.append(http_get(host, port, "/index.php", tls, cto, rto))
                row = analyze(host, port, row["scheme"], resps)
            except Exception:
                pass
        return row
    return dict(host=host, port=port, indicator=SILENT if timed_out else "TCP open, non-HTTP")


def fmt_t(s):
    s = int(s)
    return "%d:%02d:%02d" % (s // 3600, s % 3600 // 60, s % 60)


def net_main(a):
    with open(a.targets) as fh:
        targets = list(dict.fromkeys(expand(fh)))
    ports = [int(p) for p in a.ports.split(",")]
    jobs = [(h, p) for h in targets for p in ports]
    done_path = a.out + ".done"
    resume = a.resume and os.path.exists(done_path)
    skipped = 0
    if resume:
        with open(done_path) as fh:
            done = set(l.strip() for l in fh)
        skipped = len(jobs)
        jobs = [j for j in jobs if "%s:%s" % j not in done]
        skipped -= len(jobs)
    append = resume and os.path.exists(a.out)
    out = open(a.out, "a" if append else "w", newline="")
    w = csv.DictWriter(out, fieldnames=FIELDS, restval="", extrasaction="ignore")
    if not append:
        w.writeheader()
        out.flush()
    dlog = open(done_path, "a" if resume else "w")
    total, n, t0, last = len(jobs), 0, time.time(), 0.0
    cnt = dict(web=0, php=0, vuln=0, unk=0, silent=0)
    tty = sys.stderr.isatty()

    def status(final=False):
        el = time.time() - t0
        rate = n / el if el else 0
        eta = (total - n) / rate if rate else 0
        msg = "[%d/%d %5.1f%%] %4.0f/s  elapsed %s  ETA %s | web %d  PHP %d  VULN %d  unk %d  silent %d" % (
            n, total, 100.0 * n / max(total, 1), rate, fmt_t(el), fmt_t(eta),
            cnt["web"], cnt["php"], cnt["vuln"], cnt["unk"], cnt["silent"])
        sys.stderr.write(("\r\033[K" + msg + ("\n" if final else "")) if tty else msg + "\n")
        sys.stderr.flush()

    sys.stderr.write("%d targets x %d ports = %d jobs (%d skipped via --resume), %d workers -> %s\n"
                     % (len(targets), len(ports), total, skipped, a.workers, a.out))
    ex = cf.ThreadPoolExecutor(a.workers)
    futs = {ex.submit(probe, h, p, a.connect_timeout, a.timeout): (h, p) for h, p in jobs}
    try:
        for f in cf.as_completed(futs):
            h, p = futs[f]
            try:
                r = f.result()
            except Exception:
                r = None
            n += 1
            dlog.write("%s:%s\n" % (h, p))
            if r:
                if r.get("scheme"):
                    cnt["web"] += 1
                elif r["indicator"] == SILENT:
                    cnt["silent"] += 1
                st = r.get("status", "")
                if st:
                    cnt["php"] += 1
                    cnt["vuln"] += st.startswith("VULN")
                    cnt["unk"] += st == "UNKNOWN"
                    if tty:
                        sys.stderr.write("\r\033[K")
                    print("%-40s %-5s %-18s %s" % ("%s:%s" % (h, p), r["scheme"], r["php_version"] or "-", st), flush=True)
                if st or a.all:
                    w.writerow(r)
                    out.flush()
            now = time.time()
            if now - last >= (0.5 if tty else a.progress):
                dlog.flush()
                status()
                last = now
        status(final=True)
    except KeyboardInterrupt:
        sys.stderr.write("\n[!] interrupted at %d/%d - results so far are in %s; rerun with --resume to continue\n"
                         % (n, total, a.out))
        for f in futs:
            f.cancel()
    finally:
        try:
            ex.shutdown(wait=False, cancel_futures=True)
        except TypeError:
            ex.shutdown(wait=False)
        dlog.close()
        out.close()
    if cnt["silent"] > 0.5 * max(n, 1):
        sys.stderr.write("[i] >50%% of open ports never answered - firewall is answering for hosts that aren't there. "
                         "Scan from inside the segment for real results.\n")
    sys.stderr.write("Banner absence != no PHP. Treat 'local' mode as source of truth.\n")


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
    n.add_argument("-w", "--workers", type=int, default=256, help="concurrent probes (default 256)")
    n.add_argument("--connect-timeout", type=float, default=1.5, help="TCP connect + TLS handshake timeout (s)")
    n.add_argument("--timeout", type=float, default=3, help="HTTP response read timeout (s)")
    n.add_argument("--resume", action="store_true", help="skip host:port pairs already in <out>.done")
    n.add_argument("--progress", type=float, default=30, help="progress interval (s) when stderr isn't a terminal")
    n.add_argument("--all", action="store_true", help="include non-PHP responders and silent ports in CSV")
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
