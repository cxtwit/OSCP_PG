import re
import csv
import json
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from urllib.parse import urlparse


IP_RE = r'(?:\d{1,3}\.){3}\d{1,3}'


RISKY_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    81: "HTTP",
    88: "Kerberos",
    110: "POP3",
    135: "RPC",
    139: "NetBIOS",
    143: "IMAP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP",
    636: "LDAPS",
    873: "Rsync",
    3268: "Global Catalog LDAP",
    3269: "Global Catalog LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    2049: "NFS",
    2375: "Docker API",
    2376: "Docker TLS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    5985: "WinRM",
    5986: "WinRM HTTPS",
    6379: "Redis",
    7001: "WebLogic",
    8000: "HTTP",
    8080: "HTTP",
    8081: "HTTP",
    8443: "HTTPS",
    9200: "Elasticsearch",
    9300: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
}


VULN_KEYWORDS = [
    "ms17-010",
    "cve-",
    "pocscan",
    "漏洞",
    "vuln",
    "unauthorized",
    "未授权",
    "弱口令",
    "anonymous",
    "匿名",
    "rce",
    "sql injection",
    "sql注入",
    "命令执行",
    "反序列化",
    "任意文件",
    "目录遍历",
    "未授权访问",
]


CRED_KEYWORDS = [
    "username",
    "password",
    "user:",
    "pass:",
    "pwd:",
    "login",
    "credential",
    "weak password",
    "弱口令",
    "anonymous",
    "匿名登录",
]


def valid_ip(ip: str) -> bool:
    try:
        parts = ip.split(".")
        return len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts)
    except Exception:
        return False


def ip_sort_key(ip: str):
    return tuple(int(x) for x in ip.split("."))


def unique_keep_order(seq):
    seen = set()
    out = []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def one_line(text) -> str:
    return re.sub(r'\s+', ' ', str(text or '')).strip()


def shorten(text, limit=110) -> str:
    text = one_line(text)
    if len(text) <= limit:
        return text
    return text[:max(0, limit - 1)] + "…"


PORT_SERVICE_OVERRIDES = {
    53: "DNS",
    88: "Kerberos",
    135: "MSRPC",
    139: "NetBIOS/SMB",
    389: "LDAP",
    445: "SMB",
    636: "LDAPS",
    3268: "Global Catalog LDAP",
    3269: "Global Catalog LDAPS",
    3389: "RDP",
    5985: "WinRM",
    5986: "WinRM HTTPS",
}


SERVICE_ALIASES = {
    53: {"domain", "dns", "simple dns plus"},
    88: {"kerberos", "krb5"},
    135: {"rpc", "msrpc", "microsoft windows rpc"},
    139: {"netbios", "netbios-ssn", "netbios/smb"},
    389: {"ldap"},
    445: {"smb", "microsoft-ds", "microsoft windows smb2"},
    636: {"ldaps"},
    3268: {"ldap", "global catalog ldap"},
    3269: {"ldaps", "global catalog ldaps"},
    3389: {"rdp"},
    5985: {"winrm"},
    5986: {"winrm https", "winrm-https"},
}


def normalize_service(port, service=""):
    try:
        port = int(port)
    except Exception:
        return one_line(service)
    return PORT_SERVICE_OVERRIDES.get(port) or one_line(service) or RISKY_PORTS.get(port, "")


def normalize_banner(port, banner=""):
    return one_line(banner)


def extract_product(text):
    m = re.search(r'\[Product:([^\]]+)\]', text or '', re.I)
    return one_line(m.group(1)) if m else ""


def service_matches_default(port, value):
    value = one_line(value).lower()
    if not value:
        return True
    default = PORT_SERVICE_OVERRIDES.get(port, "").lower()
    aliases = SERVICE_ALIASES.get(port, set())
    return value == default or value in aliases


def service_inference_note(port_record):
    default_service = PORT_SERVICE_OVERRIDES.get(port_record.port, "")
    if not default_service:
        return ""

    observed = one_line(port_record.observed_service)
    product = extract_product(port_record.raw or port_record.banner)
    observed_differs = observed and not service_matches_default(port_record.port, observed)
    product_differs = product and not service_matches_default(port_record.port, product)

    if observed_differs or product_differs:
        originals = []
        if observed:
            originals.append(f"服务: {observed}")
        if product:
            originals.append(f"Product: {product}")
        original_text = "，".join(originals) if originals else "-"
        return f"按常见端口默认标注为 {default_service}；fscan 原始识别 {original_text}；需复核是否为非常规服务或指纹误报"

    return f"常见 {default_service} 服务"


def append_wrapped_items(lines, prefix, items, limit=112):
    items = [one_line(x) for x in items if one_line(x)]
    if not items:
        lines.append(prefix + "-")
        return

    line = prefix
    for item in items:
        extra = item if line == prefix else ", " + item
        if len(line) + len(extra) > limit and line != prefix:
            lines.append(line)
            line = prefix + item
        else:
            line += extra
    lines.append(line)


def mask_sensitive(text: str, enable_mask=True) -> str:
    if not enable_mask:
        return text

    # password: xxx / pass=xxx / pwd xxx 等
    patterns = [
        r'(?i)(password\s*[:=]\s*)([^\s,;]+)',
        r'(?i)(passwd\s*[:=]\s*)([^\s,;]+)',
        r'(?i)(pass\s*[:=]\s*)([^\s,;]+)',
        r'(?i)(pwd\s*[:=]\s*)([^\s,;]+)',
    ]

    masked = text
    for p in patterns:
        masked = re.sub(p, lambda m: m.group(1) + "******", masked)

    return masked


@dataclass
class PortRecord:
    port: int
    proto: str = "tcp"
    service: str = ""
    observed_service: str = ""
    banner: str = ""
    raw: str = ""


@dataclass
class WebRecord:
    url: str
    code: str = ""
    length: str = ""
    title: str = ""
    raw: str = ""


@dataclass
class HostRecord:
    ip: str
    alive: bool = False
    osinfo: list = field(default_factory=list)
    netinfo: list = field(default_factory=list)
    ports: dict = field(default_factory=dict)
    webs: list = field(default_factory=list)
    vulns: list = field(default_factory=list)
    creds: list = field(default_factory=list)
    raw_hits: list = field(default_factory=list)

    def add_port(self, port, proto="tcp", service="", banner="", raw=""):
        try:
            port = int(port)
        except Exception:
            return

        observed_service = one_line(service)
        service = normalize_service(port, service)
        banner = normalize_banner(port, banner)
        key = f"{port}/{proto.lower()}"
        if key not in self.ports:
            self.ports[key] = PortRecord(
                port=port,
                proto=proto.lower(),
                service=service,
                observed_service=observed_service,
                banner=banner or "",
                raw=raw or "",
            )
        else:
            old = self.ports[key]
            if service and not old.service:
                old.service = service
            if observed_service and not old.observed_service:
                old.observed_service = observed_service
            if banner and not old.banner:
                old.banner = banner
            if raw and not old.raw:
                old.raw = raw

    def add_web(self, web: WebRecord):
        exists = False
        for w in self.webs:
            if w.url == web.url and w.title == web.title:
                exists = True
                break
        if not exists:
            self.webs.append(web)

    def add_vuln(self, line):
        if line not in self.vulns:
            self.vulns.append(line)

    def add_cred(self, line):
        if line not in self.creds:
            self.creds.append(line)

    def risk_level(self):
        if self.vulns or self.creds:
            return "高"

        high_ports = {445, 3389, 5985, 5986, 6379, 27017, 9200, 11211, 2375, 5900, 1433, 3306, 5432}
        opened = {p.port for p in self.ports.values()}

        if opened & high_ports:
            return "中"
        if len(opened) >= 5:
            return "中"
        if opened:
            return "低"
        return "信息"


class FscanParser:
    def __init__(self, text: str, mask_password=True):
        self.text = text
        self.mask_password = mask_password
        self.hosts = {}
        self.interfaces = []
        self.routes = []
        self.all_ips = []
        self.unmatched_interesting = []

    def get_host(self, ip):
        if not valid_ip(ip):
            return None
        if ip not in self.hosts:
            self.hosts[ip] = HostRecord(ip=ip)
        return self.hosts[ip]

    def parse(self):
        self.extract_all_ips()
        self.extract_interfaces_and_routes()

        for raw_line in self.text.splitlines():
            line = raw_line.strip()
            if not line:
                continue

            self.parse_alive(line)
            self.parse_open_ports(line)
            self.parse_webtitle(line)
            self.parse_netinfo_osinfo(line)
            self.parse_vuln_and_creds(line)

        return self

    def extract_all_ips(self):
        ips = re.findall(IP_RE, self.text)
        ips = [ip for ip in ips if valid_ip(ip)]
        self.all_ips = unique_keep_order(ips)

    def extract_interfaces_and_routes(self):
        for raw_line in self.text.splitlines():
            line = raw_line.rstrip()

            # Get-NetIPInterface 表格
            # 14 Tailscale IPv4 Connected
            m = re.match(r'^\s*\d+\s+(?P<alias>.+?)\s+(IPv4|IPv6)\b.*', line, re.I)
            if m:
                alias = m.group("alias").strip()
                if alias and alias.lower() not in ["interfacealias"]:
                    self.interfaces.append(alias)

            # ipconfig 样式
            # Ethernet adapter Ethernet:
            m = re.search(r'(?i)\badapter\s+(.+?)\s*:', line)
            if m:
                alias = m.group(1).strip()
                if alias:
                    self.interfaces.append(alias)

            # route print 里常见的路由行
            if re.search(r'\b0\.0\.0\.0\b|\b255\.255\.255\.0\b|\bOn-link\b', line, re.I):
                if re.search(IP_RE, line):
                    self.routes.append(line.strip())

        self.interfaces = unique_keep_order(self.interfaces)
        self.routes = unique_keep_order(self.routes)

    def parse_alive(self, line):
        lower = line.lower()
        if "alive" in lower or "存活" in line or "icmp" in lower:
            for ip in re.findall(IP_RE, line):
                if valid_ip(ip):
                    h = self.get_host(ip)
                    if h:
                        h.alive = True
                        h.raw_hits.append(line)

    def parse_open_ports(self, line):
        # 常见 fscan:
        # [+] 192.168.1.1:445 open smb
        # 192.168.1.1:80 open http
        p1 = re.compile(
            rf'(?P<ip>{IP_RE})\s*:\s*(?P<port>\d{{1,5}})\s+'
            rf'(?P<state>open|开放)\b\s*(?P<svc>[A-Za-z0-9._/\-]+)?\s*(?P<banner>.*)?',
            re.I
        )

        # nmap 风格:
        # 192.168.1.1 80/tcp open http
        p2 = re.compile(
            rf'(?P<ip>{IP_RE}).*?\b(?P<port>\d{{1,5}})/(?P<proto>tcp|udp)\s+'
            rf'(?P<state>open)\b\s*(?P<svc>[A-Za-z0-9._/\-]+)?\s*(?P<banner>.*)?',
            re.I
        )

        # fscan 某些服务行:
        # [+] ssh 192.168.1.1:22 open
        p3 = re.compile(
            rf'(?i)(?P<svc>ssh|ftp|mysql|mssql|redis|postgresql|rdp|smb|ldap|telnet|mongodb|oracle|winrm|vnc)'
            rf'.*?(?P<ip>{IP_RE})\s*:\s*(?P<port>\d{{1,5}}).*?(open|开放)?'
        )

        # fscan 2.x 汇总行:
        # [*] 172.16.140.11:5985    http     [Product:...] Banner:(...)
        # [*] 172.16.140.10:636
        p4 = re.compile(
            rf'^\[\*\]\s+(?P<ip>{IP_RE})\s*:\s*(?P<port>\d{{1,5}})\s*'
            rf'(?P<svc>[A-Za-z0-9._/\-]+)?\s*(?P<banner>.*)?$',
            re.I
        )

        for pat in [p1, p2, p3, p4]:
            for m in pat.finditer(line):
                ip = m.group("ip")
                if not valid_ip(ip):
                    continue

                port = m.group("port")
                proto = m.groupdict().get("proto") or "tcp"
                svc = m.groupdict().get("svc") or ""
                banner = m.groupdict().get("banner") or ""

                h = self.get_host(ip)
                if h:
                    h.add_port(port, proto, svc, banner.strip(), line)
                    h.raw_hits.append(line)

    def parse_webtitle(self, line):
        lower = line.lower()
        if "webtitle" not in lower and "title" not in lower and "http://" not in lower and "https://" not in lower:
            return

        urls = re.findall(r'https?://[^\s\]\)\'"]+', line, re.I)
        if not urls:
            return

        for url in urls:
            clean_url = url.rstrip(",;")
            parsed = urlparse(clean_url)
            host = parsed.hostname
            if not host or not valid_ip(host):
                continue

            port = parsed.port
            if not port:
                port = 443 if parsed.scheme == "https" else 80

            code = ""
            length = ""
            title = ""

            m_code = re.search(r'(?i)\bcode[:=]\s*([0-9]{3})', line)
            if m_code:
                code = m_code.group(1)

            m_len = re.search(r'(?i)\blen(?:gth)?[:=]\s*([0-9]+)', line)
            if m_len:
                length = m_len.group(1)

            # title:xxx
            m_title = re.search(r'(?i)\btitle[:=]\s*(.+)$', line)
            if m_title:
                title = m_title.group(1).strip()
            else:
                # 有些格式是 [Title] xxx
                m_title2 = re.search(r'(?i)\[title\]\s*(.+)$', line)
                if m_title2:
                    title = m_title2.group(1).strip()

            h = self.get_host(host)
            if h:
                h.add_port(port, "tcp", "https" if parsed.scheme == "https" else "http", raw=line)
                h.add_web(WebRecord(
                    url=clean_url,
                    code=code,
                    length=length,
                    title=title,
                    raw=line
                ))
                h.raw_hits.append(line)

    def parse_netinfo_osinfo(self, line):
        lower = line.lower()

        # fscan 常见:
        # [+] NetInfo:
        # [*] OsInfo:
        if "netinfo" in lower or "osinfo" in lower or "windows" in lower or "linux" in lower:
            ips = re.findall(IP_RE, line)
            for ip in ips:
                if not valid_ip(ip):
                    continue

                h = self.get_host(ip)
                if not h:
                    continue

                if "netinfo" in lower:
                    if line not in h.netinfo:
                        h.netinfo.append(line)
                elif "osinfo" in lower or "windows" in lower or "linux" in lower:
                    if line not in h.osinfo:
                        h.osinfo.append(line)

    def parse_vuln_and_creds(self, line):
        lower = line.lower()
        ips = [ip for ip in re.findall(IP_RE, line) if valid_ip(ip)]
        is_vuln = any(k in lower for k in VULN_KEYWORDS)
        is_cred = any(k in lower for k in CRED_KEYWORDS)

        if not is_vuln and not is_cred:
            return

        safe_line = mask_sensitive(line, self.mask_password)

        if not ips:
            self.unmatched_interesting.append(safe_line)
            return

        for ip in ips:
            h = self.get_host(ip)
            if not h:
                continue

            if is_vuln:
                h.add_vuln(safe_line)
            if is_cred:
                h.add_cred(safe_line)

            h.raw_hits.append(safe_line)

    def sorted_hosts(self):
        return [self.hosts[ip] for ip in sorted(self.hosts.keys(), key=ip_sort_key)]

    def build_markdown_report(self):
        hosts = self.sorted_hosts()

        lines = []
        lines.append("# fscan 红队输出整理报告")
        lines.append("")
        lines.append("## 1. 总览")
        lines.append("")
        lines.append(f"- 唯一 IP 数：{len(self.all_ips)}")
        lines.append(f"- 识别主机数：{len(hosts)}")
        lines.append(f"- 开放端口总数：{sum(len(h.ports) for h in hosts)}")
        lines.append(f"- Web 资产数：{sum(len(h.webs) for h in hosts)}")
        lines.append(f"- 疑似漏洞记录：{sum(len(h.vulns) for h in hosts)}")
        lines.append(f"- 凭据/弱口令/匿名登录记录：{sum(len(h.creds) for h in hosts)}")
        lines.append(f"- 网卡/接口数：{len(self.interfaces)}")
        lines.append("")

        if self.interfaces:
            lines.append("## 2. 网卡 / 接口")
            lines.append("")
            for i, iface in enumerate(self.interfaces, 1):
                lines.append(f"{i}. {iface}")
            lines.append("")

        if self.routes:
            lines.append("## 3. 路由相关行")
            lines.append("")
            for r in self.routes[:100]:
                lines.append(f"- `{r}`")
            if len(self.routes) > 100:
                lines.append(f"- 另外还有 {len(self.routes) - 100} 行未展示")
            lines.append("")

        lines.append("## 4. 主机资产清单")
        lines.append("")
        lines.append("| IP | 存活 | 风险 | 开放端口 | Web 数 | 漏洞/风险记录 | 凭据记录 |")
        lines.append("|---|---:|---|---|---:|---:|---:|")

        for h in hosts:
            port_summary = ", ".join(sorted(h.ports.keys(), key=lambda x: int(x.split("/")[0])))
            if not port_summary:
                port_summary = "-"
            lines.append(
                f"| {h.ip} | {'是' if h.alive else '-'} | {h.risk_level()} | "
                f"{port_summary} | {len(h.webs)} | {len(h.vulns)} | {len(h.creds)} |"
            )
        lines.append("")

        lines.append("## 5. 详细信息")
        lines.append("")

        for h in hosts:
            lines.append(f"### {h.ip}")
            lines.append("")
            lines.append(f"- 存活：{'是' if h.alive else '-'}")
            lines.append(f"- 风险等级：{h.risk_level()}")
            lines.append("")

            if h.ports:
                lines.append("#### 开放端口")
                lines.append("")
                lines.append("| 端口 | 协议 | 服务 | 备注 |")
                lines.append("|---:|---|---|---|")
                for key in sorted(h.ports.keys(), key=lambda x: int(x.split("/")[0])):
                    p = h.ports[key]
                    service = p.service or RISKY_PORTS.get(p.port, "")
                    note = service_inference_note(p)
                    if p.banner:
                        banner_note = p.banner.replace("|", "/")[:120]
                        note = f"{note}；{banner_note}" if note else banner_note
                    lines.append(f"| {p.port} | {p.proto} | {service} | {note} |")
                lines.append("")

            if h.webs:
                lines.append("#### Web 资产")
                lines.append("")
                lines.append("| URL | Code | Length | Title |")
                lines.append("|---|---|---:|---|")
                for w in h.webs:
                    title = w.title.replace("|", "/")[:160] if w.title else ""
                    lines.append(f"| {w.url} | {w.code} | {w.length} | {title} |")
                lines.append("")

            if h.osinfo:
                lines.append("#### OS 信息")
                lines.append("")
                for x in unique_keep_order(h.osinfo):
                    lines.append(f"- `{x}`")
                lines.append("")

            if h.netinfo:
                lines.append("#### NetInfo 信息")
                lines.append("")
                for x in unique_keep_order(h.netinfo):
                    lines.append(f"- `{x}`")
                lines.append("")

            if h.vulns:
                lines.append("#### 疑似漏洞 / 风险记录")
                lines.append("")
                for x in unique_keep_order(h.vulns):
                    lines.append(f"- `{x}`")
                lines.append("")

            if h.creds:
                lines.append("#### 凭据 / 弱口令 / 匿名登录记录")
                lines.append("")
                for x in unique_keep_order(h.creds):
                    lines.append(f"- `{x}`")
                lines.append("")

        if self.unmatched_interesting:
            lines.append("## 6. 未绑定到具体 IP 的风险行")
            lines.append("")
            for x in unique_keep_order(self.unmatched_interesting):
                lines.append(f"- `{x}`")
            lines.append("")

        lines.append("## 7. 红队整理建议")
        lines.append("")
        lines.append("- 优先关注风险等级为“高”的主机。")
        lines.append("- 优先复核包含弱口令、匿名访问、未授权、CVE、PocScan 命中的记录。")
        lines.append("- 对 445、3389、6379、27017、9200、2375、11211 等端口单独建立资产清单。")
        lines.append("- Web 资产建议继续按系统名称、标题、状态码进行分类。")
        lines.append("- 报告中的凭据默认已脱敏，如需原文可关闭脱敏选项。")

        return "\n".join(lines)

    def build_readable_report(self):
        hosts = self.sorted_hosts()
        risk_order = {"高": 0, "中": 1, "低": 2, "信息": 3}
        ordered_hosts = sorted(hosts, key=lambda h: (risk_order.get(h.risk_level(), 9), ip_sort_key(h.ip)))
        risky_hosts = [h for h in ordered_hosts if h.risk_level() in {"高", "中"}]
        web_hosts = [h for h in ordered_hosts if h.webs]
        interesting_hosts = [h for h in ordered_hosts if h.vulns or h.creds]

        lines = []
        lines.append("fscan 输出速览")
        lines.append("=" * 72)
        lines.append(
            f"总览：唯一 IP {len(self.all_ips)} 个｜识别主机 {len(hosts)} 个｜"
            f"开放端口 {sum(len(h.ports) for h in hosts)} 个｜Web {sum(len(h.webs) for h in hosts)} 个"
        )
        lines.append(
            f"风险：疑似漏洞 {sum(len(h.vulns) for h in hosts)} 条｜"
            f"凭据/弱口令/匿名登录 {sum(len(h.creds) for h in hosts)} 条｜接口 {len(self.interfaces)} 个"
        )
        lines.append("")

        lines.append("一、优先看这里")
        lines.append("-" * 72)
        if not risky_hosts:
            lines.append("暂无高/中风险主机；可以直接看后面的端口和 Web 资产。")
        else:
            for h in risky_hosts:
                lines.extend(self.format_host_card(h, include_findings=True))
        lines.append("")

        lines.append("二、Web 资产")
        lines.append("-" * 72)
        if not web_hosts:
            lines.append("未识别到 Web 资产。")
        else:
            for h in web_hosts:
                lines.append(f"[{h.risk_level()}] {h.ip}")
                for w in h.webs:
                    meta = []
                    if w.code:
                        meta.append(f"code {w.code}")
                    if w.length:
                        meta.append(f"len {w.length}")
                    if w.title:
                        meta.append(f"title {shorten(w.title, 60)}")
                    suffix = "  " + "｜".join(meta) if meta else ""
                    lines.append(f"  - {shorten(w.url, 82)}{suffix}")
        lines.append("")

        lines.append("三、主机端口清单")
        lines.append("-" * 72)
        if not hosts:
            lines.append("未识别到主机。")
        else:
            for h in ordered_hosts:
                ports = [self.format_port(p) for p in sorted(h.ports.values(), key=lambda p: p.port)]
                alive = "存活" if h.alive else "未确认存活"
                lines.append(f"[{h.risk_level()}] {h.ip}  {alive}  端口:{len(h.ports)}  Web:{len(h.webs)}")
                append_wrapped_items(lines, "    ", ports)
        lines.append("")

        if interesting_hosts or self.unmatched_interesting:
            lines.append("四、风险/凭据原文")
            lines.append("-" * 72)
            for h in interesting_hosts:
                lines.append(f"[{h.risk_level()}] {h.ip}")
                for x in unique_keep_order(h.vulns):
                    lines.append(f"  - 漏洞：{shorten(x, 118)}")
                for x in unique_keep_order(h.creds):
                    lines.append(f"  - 凭据：{shorten(x, 118)}")
            if self.unmatched_interesting:
                lines.append("未绑定 IP：")
                for x in unique_keep_order(self.unmatched_interesting):
                    lines.append(f"  - {shorten(x, 118)}")
            lines.append("")

        if self.interfaces or self.routes:
            lines.append("五、网卡/路由")
            lines.append("-" * 72)
            if self.interfaces:
                append_wrapped_items(lines, "接口：", self.interfaces)
            if self.routes:
                lines.append("路由相关行：")
                for r in self.routes[:30]:
                    lines.append(f"  - {shorten(r, 118)}")
                if len(self.routes) > 30:
                    lines.append(f"  - 另外还有 {len(self.routes) - 30} 行未展示，导出 Markdown 可看完整内容。")
            lines.append("")

        lines.append("建议：先复核高风险主机里的弱口令、匿名访问、未授权、CVE/PocScan 命中，再按 Web 资产继续验证。")
        lines.append("需要提交或留档时，用上方“导出 Markdown/CSV/JSON”。")
        return "\n".join(lines)

    def format_host_card(self, h, include_findings=False):
        lines = []
        alive = "存活" if h.alive else "未确认存活"
        lines.append(f"[{h.risk_level()}] {h.ip}  {alive}  端口:{len(h.ports)}  Web:{len(h.webs)}")

        ports = [self.format_port(p) for p in sorted(h.ports.values(), key=lambda p: p.port)]
        append_wrapped_items(lines, "  端口：", ports)

        if h.webs:
            web_items = []
            for w in h.webs[:5]:
                title = f" ({shorten(w.title, 38)})" if w.title else ""
                web_items.append(shorten(w.url, 70) + title)
            append_wrapped_items(lines, "  Web ：", web_items)
            if len(h.webs) > 5:
                lines.append(f"  Web ：另外还有 {len(h.webs) - 5} 个，见 Web 资产段。")

        if include_findings:
            findings = [shorten(x, 96) for x in unique_keep_order(h.vulns + h.creds)[:4]]
            if findings:
                for x in findings:
                    lines.append(f"  风险：{x}")
                if len(h.vulns) + len(h.creds) > 4:
                    lines.append(f"  风险：另外还有 {len(h.vulns) + len(h.creds) - 4} 条，见风险/凭据原文段。")
        return lines

    def format_port(self, p):
        service = p.service or RISKY_PORTS.get(p.port, "")
        label = f"{p.port}/{p.proto}"
        if service:
            label += f" {service}"
        if p.port in RISKY_PORTS:
            label += "*"
        if service_inference_note(p) and "原始识别" in service_inference_note(p):
            original = p.observed_service or extract_product(p.raw or p.banner) or "-"
            label += f"（默认；原始:{original}）"
        return label

    def build_ports_copy_text(self):
        rows = []

        for h in self.sorted_hosts():
            status = "up" if h.alive else "unknown"
            rows.append(f"Host: {h.ip}  Status: {status}")

            ports = sorted(h.ports.values(), key=lambda p: p.port)
            if not ports:
                rows.append("No open ports parsed.")
                rows.append("")
                continue

            rows.append("PORT      STATE SERVICE  NOTE")
            for p in ports:
                service = p.service or RISKY_PORTS.get(p.port, "unknown")
                line = f"{p.port}/{p.proto}".ljust(10) + "open  " + service.ljust(8)

                correction = self.port_correction_note(p)
                if correction:
                    line += f"  [纠正: {correction}]"
                elif p.banner:
                    line += f"  {shorten(p.banner, 80)}"

                rows.append(line.rstrip())

            if h.webs:
                rows.append("Web:")
                for w in h.webs:
                    meta = []
                    if w.code:
                        meta.append(w.code)
                    if w.title:
                        meta.append(shorten(w.title, 60))
                    suffix = f" ({' / '.join(meta)})" if meta else ""
                    rows.append(f"  {w.url}{suffix}")

            if h.vulns or h.creds:
                rows.append("Findings:")
                for x in unique_keep_order(h.vulns):
                    rows.append(f"  vuln: {shorten(x, 120)}")
                for x in unique_keep_order(h.creds):
                    rows.append(f"  cred: {shorten(x, 120)}")

            rows.append("")

        return "\n".join(rows).rstrip()

    def port_correction_note(self, p):
        default_service = PORT_SERVICE_OVERRIDES.get(p.port, "")
        if not default_service:
            return ""

        observed = one_line(p.observed_service)
        product = extract_product(p.raw or p.banner)
        originals = unique_keep_order([x for x in [observed, product] if x])
        if not any(not service_matches_default(p.port, x) for x in originals):
            return ""

        original_text = "/".join(originals) if originals else "-"
        return f"原始 {original_text} -> {default_service}"

    def to_json_obj(self):
        obj = {
            "summary": {
                "unique_ips": len(self.all_ips),
                "hosts": len(self.hosts),
                "interfaces": self.interfaces,
                "routes": self.routes,
            },
            "hosts": []
        }

        for h in self.sorted_hosts():
            hd = {
                "ip": h.ip,
                "alive": h.alive,
                "risk": h.risk_level(),
                "ports": [asdict(p) for p in h.ports.values()],
                "webs": [asdict(w) for w in h.webs],
                "osinfo": h.osinfo,
                "netinfo": h.netinfo,
                "vulns": h.vulns,
                "creds": h.creds,
            }
            obj["hosts"].append(hd)

        return obj


class App:
    def __init__(self, root):
        self.root = root
        self.root.title("红队 fscan 输出整理器 - 本地离线版")
        self.root.geometry("1320x850")

        self.parser = None
        self.sort_reverse = {}
        self.create_widgets()

    def create_widgets(self):
        outer = ttk.Frame(self.root, padding=8)
        outer.pack(fill=tk.BOTH, expand=True)

        toolbar = ttk.Frame(outer)
        toolbar.pack(fill=tk.X, pady=(0, 8))

        self.mask_var = tk.BooleanVar(value=True)

        ttk.Button(toolbar, text="整理", command=self.do_parse).pack(side=tk.LEFT)
        ttk.Button(toolbar, text="加载示例", command=self.load_sample).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="清空", command=self.clear_all).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="复制清单", command=self.copy_report).pack(side=tk.LEFT, padx=5)

        ttk.Separator(toolbar, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=8)

        ttk.Button(toolbar, text="导出 Markdown", command=self.export_markdown).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="导出端口 CSV", command=self.export_ports_csv).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="导出 Web CSV", command=self.export_web_csv).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="导出 JSON", command=self.export_json).pack(side=tk.LEFT, padx=5)

        ttk.Checkbutton(toolbar, text="脱敏密码", variable=self.mask_var).pack(side=tk.LEFT, padx=12)

        pane = ttk.PanedWindow(outer, orient=tk.HORIZONTAL)
        pane.pack(fill=tk.BOTH, expand=True)

        left = ttk.Frame(pane)
        right = ttk.Frame(pane)

        pane.add(left, weight=1)
        pane.add(right, weight=1)

        ttk.Label(left, text="原始输出：粘贴 fscan / PowerShell / route print / ipconfig 等结果").pack(anchor="w")
        self.input_text = scrolledtext.ScrolledText(left, wrap=tk.WORD, font=("Consolas", 10))
        self.input_text.pack(fill=tk.BOTH, expand=True, pady=(4, 0))

        ttk.Label(right, text="可复制端口清单：右侧点一下，Ctrl+A / Ctrl+C 直接复制").pack(anchor="w")
        self.output_text = scrolledtext.ScrolledText(right, wrap=tk.NONE, font=("Consolas", 12))
        self.output_text.pack(fill=tk.BOTH, expand=True, pady=(4, 0))

        self.load_sample()

    def get_input(self):
        return self.input_text.get("1.0", tk.END)

    def do_parse(self):
        raw = self.get_input()
        if not raw.strip():
            messagebox.showinfo("提示", "请先粘贴 fscan 输出。")
            return

        self.parser = FscanParser(raw, mask_password=self.mask_var.get()).parse()
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, self.parser.build_ports_copy_text())

    def clear_all(self):
        self.input_text.delete("1.0", tk.END)
        self.clear_results()
        self.parser = None

    def clear_results(self):
        self.output_text.delete("1.0", tk.END)

    def populate_host_table(self):
        self.clear_results()
        if not self.parser:
            return

        hosts = sorted(self.parser.sorted_hosts(), key=lambda h: (self.risk_rank(h.risk_level()), ip_sort_key(h.ip)))
        for h in hosts:
            tags = (f"risk_{h.risk_level()}",)
            self.host_table.insert("", tk.END, iid=h.ip, values=(
                h.ip,
                self.port_numbers_summary(h),
            ), tags=tags)

        children = self.host_table.get_children()
        if children:
            self.host_table.selection_set(children[0])
            self.host_table.focus(children[0])
            self.host_table.see(children[0])
            self.show_host_detail(children[0])
        else:
            self.detail_text.insert(tk.END, "没解析到主机。")

    def risk_rank(self, risk):
        return {"高": 0, "中": 1, "低": 2, "信息": 3}.get(risk, 9)

    def port_summary(self, h):
        ports = [self.parser.format_port(p) for p in sorted(h.ports.values(), key=lambda p: p.port)]
        return ", ".join(ports) if ports else "-"

    def port_numbers_summary(self, h):
        ports = sorted({p.port for p in h.ports.values()})
        return ",  ".join(str(port) for port in ports) if ports else "-"

    def finding_summary(self, h):
        parts = []
        if h.vulns:
            parts.append(f"漏洞{len(h.vulns)}")
        if h.creds:
            parts.append(f"凭据{len(h.creds)}")
        return "/".join(parts) if parts else "-"

    def important_note(self, h):
        if h.vulns:
            return shorten(h.vulns[0], 90)
        if h.creds:
            return shorten(h.creds[0], 90)

        risky = []
        for p in sorted(h.ports.values(), key=lambda x: x.port):
            if p.port in RISKY_PORTS:
                risky.append(f"{p.port}/{RISKY_PORTS[p.port]}")
        return ", ".join(risky[:8]) if risky else "-"

    def on_host_select(self, _event=None):
        selected = self.host_table.selection()
        if selected:
            self.show_host_detail(selected[0])

    def show_host_detail(self, ip):
        self.detail_text.delete("1.0", tk.END)
        if not self.parser or ip not in self.parser.hosts:
            return
        self.detail_text.insert(tk.END, self.build_host_detail(self.parser.hosts[ip]))

    def build_host_detail(self, h):
        lines = []
        lines.append(f"IP：{h.ip}    风险：{h.risk_level()}    存活：{'是' if h.alive else '-'}")
        lines.append("=" * 78)

        lines.append("开放端口：")
        if h.ports:
            for p in sorted(h.ports.values(), key=lambda x: x.port):
                service = p.service or RISKY_PORTS.get(p.port, "")
                port_line = f"  - {p.port}/{p.proto}"
                if service:
                    port_line += f"  {service}"
                if p.port in RISKY_PORTS:
                    port_line += f"  [{RISKY_PORTS[p.port]}]"
                lines.append(port_line)
                inference_note = service_inference_note(p)
                if inference_note:
                    lines.append(f"      说明：{shorten(inference_note, 180)}")
                if p.banner:
                    lines.append(f"      Banner：{shorten(p.banner, 140)}")
        else:
            lines.append("  - 无")

        lines.append("")
        lines.append("Web 资产：")
        if h.webs:
            for w in h.webs:
                meta = []
                if w.code:
                    meta.append(f"code {w.code}")
                if w.length:
                    meta.append(f"len {w.length}")
                if w.title:
                    meta.append(f"title {shorten(w.title, 80)}")
                suffix = "  " + "｜".join(meta) if meta else ""
                lines.append(f"  - {w.url}{suffix}")
        else:
            lines.append("  - 无")

        if h.vulns or h.creds:
            lines.append("")
            lines.append("风险/凭据原文：")
            for x in unique_keep_order(h.vulns):
                lines.append(f"  - 漏洞：{shorten(x, 150)}")
            for x in unique_keep_order(h.creds):
                lines.append(f"  - 凭据：{shorten(x, 150)}")

        if h.osinfo:
            lines.append("")
            lines.append("OS 信息：")
            for x in unique_keep_order(h.osinfo):
                lines.append(f"  - {shorten(x, 150)}")

        if h.netinfo:
            lines.append("")
            lines.append("NetInfo 信息：")
            for x in unique_keep_order(h.netinfo):
                lines.append(f"  - {shorten(x, 150)}")

        return "\n".join(lines)

    def sort_table(self, col):
        items = list(self.host_table.get_children())
        if not items:
            return

        reverse = self.sort_reverse.get(col, False)

        def key(item):
            value = self.host_table.set(item, col)
            if col == "risk":
                return self.risk_rank(value)
            if col == "ports":
                nums = [int(x) for x in re.findall(r'\d+', value)]
                return nums or [0]
            if col == "ip" and valid_ip(value):
                return ip_sort_key(value)
            return value

        for index, item in enumerate(sorted(items, key=key, reverse=reverse)):
            self.host_table.move(item, "", index)
        self.sort_reverse[col] = not reverse

    def copy_report(self):
        content = self.output_text.get("1.0", tk.END).strip()
        if not content:
            messagebox.showinfo("提示", "右侧清单为空。")
            return

        self.root.clipboard_clear()
        self.root.clipboard_append(content)
        self.root.update()
        messagebox.showinfo("提示", "端口清单已复制，可直接粘贴到 Excel / Word / Markdown。")

    def ensure_parsed(self):
        if self.parser is None:
            self.do_parse()
        return self.parser is not None

    def export_markdown(self):
        if not self.ensure_parsed():
            return

        path = filedialog.asksaveasfilename(
            defaultextension=".md",
            filetypes=[("Markdown", "*.md"), ("Text", "*.txt"), ("All files", "*.*")]
        )
        if not path:
            return

        with open(path, "w", encoding="utf-8") as f:
            f.write(self.parser.build_markdown_report())

        messagebox.showinfo("导出完成", f"已导出：{path}")

    def export_ports_csv(self):
        if not self.ensure_parsed():
            return

        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv"), ("All files", "*.*")]
        )
        if not path:
            return

        with open(path, "w", encoding="utf-8-sig", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["IP", "Risk", "Alive", "Port", "Proto", "Service", "ObservedService", "Note", "Banner/Raw"])

            for h in self.parser.sorted_hosts():
                for p in h.ports.values():
                    writer.writerow([
                        h.ip,
                        h.risk_level(),
                        "yes" if h.alive else "",
                        p.port,
                        p.proto,
                        p.service,
                        p.observed_service,
                        service_inference_note(p),
                        p.banner or p.raw,
                    ])

        messagebox.showinfo("导出完成", f"已导出：{path}")

    def export_web_csv(self):
        if not self.ensure_parsed():
            return

        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv"), ("All files", "*.*")]
        )
        if not path:
            return

        with open(path, "w", encoding="utf-8-sig", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["IP", "Risk", "URL", "Code", "Length", "Title", "Raw"])

            for h in self.parser.sorted_hosts():
                for w in h.webs:
                    writer.writerow([
                        h.ip,
                        h.risk_level(),
                        w.url,
                        w.code,
                        w.length,
                        w.title,
                        w.raw,
                    ])

        messagebox.showinfo("导出完成", f"已导出：{path}")

    def export_json(self):
        if not self.ensure_parsed():
            return

        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("All files", "*.*")]
        )
        if not path:
            return

        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.parser.to_json_obj(), f, ensure_ascii=False, indent=2)

        messagebox.showinfo("导出完成", f"已导出：{path}")

    def load_sample(self):
        sample = """[+] 192.168.140.122:445 open smb
[+] 192.168.140.122:3389 open rdp
[+] 192.168.140.122:135 open msrpc
[+] 192.168.140.10:80 open http
[+] 192.168.140.10:3306 open mysql
[*] WebTitle: http://192.168.140.10:80 code:200 len:10240 title:内部管理系统
[+] Redis unauthorized access 192.168.140.20:6379
[+] 192.168.140.30:21 open ftp
[+] ftp 192.168.140.30:21 anonymous login
[+] PocScan 192.168.140.40 MS17-010
[+] 192.168.140.50:8080 open http
[*] WebTitle: http://192.168.140.50:8080 code:302 len:512 title:Login
[+] mysql 192.168.140.10:3306 username:root password:root123

 14 Tailscale                              IPv4                       Connected
 14 Tailscale                              IPv6                       Connected
  8 Radmin VPN                             IPv4                       Connected
 29 WLAN                                   IPv4                       Connected

0.0.0.0          0.0.0.0      192.168.1.1     192.168.1.100     35
192.168.140.0    255.255.255.0      On-link   100.64.1.2        5
"""
        self.input_text.delete("1.0", tk.END)
        self.input_text.insert(tk.END, sample)


def main():
    root = tk.Tk()
    app = App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
