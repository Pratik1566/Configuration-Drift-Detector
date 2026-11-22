
"""
Drift Detector - Standard Security Baseline

Contains the built-in security baseline definitions.
Planned coverage:
- Ubuntu 22.04: 53 rules
- SSH Server: 49 rules
- NGINX CIS 2.5: 4 rules

Total: 106 rules
"""

BASELINE_VERSION = "1.0"

BASELINE_COUNTS = {
    "ubuntu_22_04": 53,
    "ssh": 49,
    "nginx": 4,
    "total": 106,
    "automatic": 91,
    "manual": 15,
}

# Every rule must follow this structure.
RULE_TEMPLATE = {
    "id": None,
    "platform": None,
    "category": None,
    "title": None,
    "setting": None,
    "expected": None,
    "severity": None,
    "automatic": None,
    "check_type": None,
    "description": None,
    "source": None,
}

# Built-in security rules.
# We will populate these with verified expected values.
STANDARD_SECURITY_BASELINE = {

"ubuntu_22_04": [
    # ==========================================
    # A. IPv4 NETWORK SECURITY (27 RULES)
    # ==========================================

    {
        "id": "UBU-001", "platform": "Ubuntu 22.04",
        "category": "IPv4 Network", "title": "Disable IP forwarding",
        "setting": "net.ipv4.ip_forward", "expected": 0,
        "severity": "High", "automatic": True,
        "check_type": "equals",
        "description": "Prevents IPv4 packet forwarding.",
        "source": "Ubuntu 22.04 security baseline"
    },
    {
        "id": "UBU-002", "platform": "Ubuntu 22.04",
        "category": "IPv4 Network", "title": "Disable all-interface forwarding",
        "setting": "net.ipv4.conf.all.forwarding", "expected": 0,
        "severity": "High", "automatic": True,
        "check_type": "equals",
        "description": "Disables IPv4 forwarding on all interfaces.",
        "source": "Ubuntu 22.04 security baseline"
    },
    {
        "id": "UBU-003", "platform": "Ubuntu 22.04",
        "category": "IPv4 Network", "title": "Enable reverse path filtering",
        "setting": "net.ipv4.conf.all.rp_filter", "expected": 1,
        "severity": "Medium", "automatic": True,
        "check_type": "equals",
        "description": "Enables reverse path filtering.",
        "source": "Ubuntu 22.04 security baseline"
    },
    {
        "id": "UBU-004", "platform": "Ubuntu 22.04",
        "category": "IPv4 Network", "title": "Enable default reverse path filtering",
        "setting": "net.ipv4.conf.default.rp_filter", "expected": 1,
        "severity": "Medium", "automatic": True,
        "check_type": "equals",
        "description": "Enables reverse path filtering by default.",
        "source": "Ubuntu 22.04 security baseline"
    },
    {
        "id": "UBU-005", "platform": "Ubuntu 22.04",
        "category": "IPv4 Network", "title": "Ignore bogus ICMP errors",
        "setting": "net.ipv4.icmp_ignore_bogus_error_responses", "expected": 1,
        "severity": "Low", "automatic": True,
        "check_type": "equals",
        "description": "Ignores bogus ICMP error responses.",
        "source": "Ubuntu 22.04 security baseline"
    },
    {
        "id": "UBU-006", "platform": "Ubuntu 22.04",
        "category": "IPv4 Network", "title": "Ignore ICMP broadcast requests",
        "setting": "net.ipv4.icmp_echo_ignore_broadcasts", "expected": 1,
        "severity": "Medium", "automatic": True,
        "check_type": "equals",
        "description": "Ignores ICMP echo requests sent to broadcast addresses.",
        "source": "Ubuntu 22.04 security baseline"
    },
    {
        "id": "UBU-007", "platform": "Ubuntu 22.04",
        "category": "IPv4 Network", "title": "Set ICMP rate limit",
        "setting": "net.ipv4.icmp_ratelimit", "expected": 100,
        "severity": "Low", "automatic": True,
        "check_type": "equals",
        "description": "Controls the ICMP response rate limit.",
        "source": "Ubuntu 22.04 security baseline"
    },
    {
        "id": "UBU-008", "platform": "Ubuntu 22.04",
        "category": "IPv4 Network", "title": "Set ICMP rate mask",
        "setting": "net.ipv4.icmp_ratemask", "expected": 88089,
        "severity": "Low", "automatic": True,
        "check_type": "equals",
        "description": "Controls which ICMP types are rate limited.",
        "source": "Ubuntu 22.04 security baseline"
    },
    {
        "id": "UBU-009", "platform": "Ubuntu 22.04",
        "category": "IPv4 Network", "title": "Disable TCP timestamps",
        "setting": "net.ipv4.tcp_timestamps", "expected": 0,
        "severity": "Medium", "automatic": True,
        "check_type": "equals",
        "description": "Disables TCP timestamps.",
        "source": "Ubuntu 22.04 security baseline"
    },
    {
        "id": "UBU-010", "platform": "Ubuntu 22.04",
        "category": "IPv4 Network", "title": "Configure ARP ignore",
        "setting": "net.ipv4.conf.all.arp_ignore", "expected": [1, 2],
        "severity": "Medium", "automatic": True,
        "check_type": "one_of",
        "description": "Restricts ARP responses to local addresses.",
        "source": "Ubuntu 22.04 security baseline"
    },
    {
        "id": "UBU-011", "platform": "Ubuntu 22.04",
        "category": "IPv4 Network", "title": "Configure ARP announce",
        "setting": "net.ipv4.conf.all.arp_announce", "expected": 2,
        "severity": "Medium", "automatic": True,
        "check_type": "equals",
        "description": "Restricts ARP announcements to appropriate local addresses.",
        "source": "Ubuntu 22.04 security baseline"
    },
    {
        "id": "UBU-012", "platform": "Ubuntu 22.04",
        "category": "IPv4 Network", "title": "Enable TCP RFC1337 protection",
        "setting": "net.ipv4.tcp_rfc1337", "expected": 1,
        "severity": "Medium", "automatic": True,
        "check_type": "equals",
        "description": "Enables protection described by TCP RFC 1337.",
        "source": "Ubuntu 22.04 security baseline"
    },
    {
        "id": "UBU-013", "platform": "Ubuntu 22.04",
        "category": "IPv4 Network", "title": "Enable TCP SYN cookies",
        "setting": "net.ipv4.tcp_syncookies", "expected": 1,
        "severity": "High", "automatic": True,
        "check_type": "equals",
        "description": "Enables SYN cookies to help mitigate SYN flood attacks.",
        "source": "Ubuntu 22.04 security baseline"
    },
    {
        "id": "UBU-014", "platform": "Ubuntu 22.04",
        "category": "IPv4 Network", "title": "Configure all shared media",
        "setting": "net.ipv4.conf.all.shared_media", "expected": 1,
        "severity": "Low", "automatic": True,
        "check_type": "equals",
        "description": "Configures shared media handling.",
        "source": "Ubuntu 22.04 security baseline"
    },
    {
        "id": "UBU-015", "platform": "Ubuntu 22.04",
        "category": "IPv4 Network", "title": "Configure default shared media",
        "setting": "net.ipv4.conf.default.shared_media", "expected": 1,
        "severity": "Low", "automatic": True,
        "check_type": "equals",
        "description": "Configures default shared media handling.",
        "source": "Ubuntu 22.04 security baseline"
    },
    {
        "id": "UBU-016", "platform": "Ubuntu 22.04",
        "category": "IPv4 Network", "title": "Disable source routing on all interfaces",
        "setting": "net.ipv4.conf.all.accept_source_route", "expected": 0,
        "severity": "High", "automatic": True,
        "check_type": "equals",
        "description": "Disables IPv4 source-routed packets on all interfaces.",
        "source": "Ubuntu 22.04 security baseline"
    },
    {
        "id": "UBU-017", "platform": "Ubuntu 22.04",
        "category": "IPv4 Network", "title": "Disable default source routing",
        "setting": "net.ipv4.conf.default.accept_source_route", "expected": 0,
        "severity": "High", "automatic": True,
        "check_type": "equals",
        "description": "Disables IPv4 source routing by default.",
        "source": "Ubuntu 22.04 security baseline"
    },
    {
        "id": "UBU-018", "platform": "Ubuntu 22.04",
        "category": "IPv6 Network", "title": "Disable IPv6 source routing on all interfaces",
        "setting": "net.ipv6.conf.all.accept_source_route", "expected": 0,
        "severity": "High", "automatic": True,
        "check_type": "equals",
        "description": "Disables IPv6 source-routed packets on all interfaces.",
        "source": "Ubuntu 22.04 security baseline"
    },
    {
        "id": "UBU-019", "platform": "Ubuntu 22.04",
        "category": "IPv6 Network", "title": "Disable default IPv6 source routing",
        "setting": "net.ipv6.conf.default.accept_source_route", "expected": 0,
        "severity": "High", "automatic": True,
        "check_type": "equals",
        "description": "Disables IPv6 source routing by default.",
        "source": "Ubuntu 22.04 security baseline"
    },
    {
        "id": "UBU-020", "platform": "Ubuntu 22.04",
        "category": "IPv4 Network", "title": "Disable default ICMP redirects",
        "setting": "net.ipv4.conf.default.accept_redirects", "expected": 0,
        "severity": "High", "automatic": True,
        "check_type": "equals",
        "description": "Disables acceptance of ICMP redirects by default.",
        "source": "Ubuntu 22.04 security baseline"
    },
    {
        "id": "UBU-021", "platform": "Ubuntu 22.04",
        "category": "IPv4 Network", "title": "Disable ICMP redirects",
        "setting": "net.ipv4.conf.all.accept_redirects", "expected": 0,
        "severity": "High", "automatic": True,
        "check_type": "equals",
        "description": "Disables acceptance of ICMP redirects on all interfaces.",
        "source": "Ubuntu 22.04 security baseline"
    },
    {
        "id": "UBU-022", "platform": "Ubuntu 22.04",
        "category": "IPv4 Network", "title": "Disable secure ICMP redirects",
        "setting": "net.ipv4.conf.all.secure_redirects", "expected": 0,
        "severity": "Medium", "automatic": True,
        "check_type": "equals",
        "description": "Disables acceptance of secure ICMP redirects.",
        "source": "Ubuntu 22.04 security baseline"
    },
    {
        "id": "UBU-023", "platform": "Ubuntu 22.04",
        "category": "IPv4 Network", "title": "Disable default secure redirects",
        "setting": "net.ipv4.conf.default.secure_redirects", "expected": 0,
        "severity": "Medium", "automatic": True,
        "check_type": "equals",
        "description": "Disables secure ICMP redirects by default.",
        "source": "Ubuntu 22.04 security baseline"
    },
    {
        "id": "UBU-024", "platform": "Ubuntu 22.04",
        "category": "IPv4 Network", "title": "Disable default ICMP send redirects",
        "setting": "net.ipv4.conf.default.send_redirects", "expected": 0,
        "severity": "Medium", "automatic": True,
        "check_type": "equals",
        "description": "Prevents sending ICMP redirects by default.",
        "source": "Ubuntu 22.04 security baseline"
    },
    {
        "id": "UBU-025", "platform": "Ubuntu 22.04",
        "category": "IPv4 Network", "title": "Disable ICMP send redirects",
        "setting": "net.ipv4.conf.all.send_redirects", "expected": 0,
        "severity": "Medium", "automatic": True,
        "check_type": "equals",
        "description": "Prevents sending ICMP redirects on all interfaces.",
        "source": "Ubuntu 22.04 security baseline"
    },
    {
        "id": "UBU-026", "platform": "Ubuntu 22.04",
        "category": "IPv4 Network", "title": "Enable martian packet logging",
        "setting": "net.ipv4.conf.all.log_martians", "expected": 1,
        "severity": "Low", "automatic": True,
        "check_type": "equals",
        "description": "Logs suspicious packets with impossible addresses.",
        "source": "Ubuntu 22.04 security baseline"
    },
    {
        "id": "UBU-027", "platform": "Ubuntu 22.04",
        "category": "IPv4 Network", "title": "Enable default martian packet logging",
        "setting": "net.ipv4.conf.default.log_martians", "expected": 1,
        "severity": "Low", "automatic": True,
        "check_type": "equals",
        "description": "Enables martian packet logging by default.",
        "source": "Ubuntu 22.04 security baseline"
    },

    # ==========================================
    # B. IPv6 NETWORK SECURITY (14 RULES)
    # ==========================================

    {
        "id": "UBU-028", "platform": "Ubuntu 22.04",
        "category": "IPv6 Network", "title": "Disable IPv6 forwarding",
        "setting": "net.ipv6.conf.all.forwarding", "expected": 0,
        "severity": "High", "automatic": True,
        "check_type": "equals",
        "description": "Disables IPv6 packet forwarding.",
        "source": "Ubuntu 22.04 security baseline"
    },
    {
        "id": "UBU-029", "platform": "Ubuntu 22.04",
        "category": "IPv6 Network", "title": "Disable default IPv6 redirects",
        "setting": "net.ipv6.conf.default.accept_redirects", "expected": 0,
        "severity": "High", "automatic": True,
        "check_type": "equals",
        "description": "Disables IPv6 redirect acceptance by default.",
        "source": "Ubuntu 22.04 security baseline"
    },
    {
        "id": "UBU-030", "platform": "Ubuntu 22.04",
        "category": "IPv6 Network", "title": "Disable IPv6 redirects",
        "setting": "net.ipv6.conf.all.accept_redirects", "expected": 0,
        "severity": "High", "automatic": True,
        "check_type": "equals",
        "description": "Disables IPv6 redirect acceptance on all interfaces.",
        "source": "Ubuntu 22.04 security baseline"
    },
    {
        "id": "UBU-031", "platform": "Ubuntu 22.04",
        "category": "IPv6 Network", "title": "Disable default router solicitations",
        "setting": "net.ipv6.conf.default.router_solicitations", "expected": 0,
        "severity": "Low", "automatic": True,
        "check_type": "equals",
        "description": "Sets default IPv6 router solicitation count to zero.",
        "source": "Ubuntu 22.04 security baseline"
    },
    {
        "id": "UBU-032", "platform": "Ubuntu 22.04",
        "category": "IPv6 Network", "title": "Disable router solicitations",
        "setting": "net.ipv6.conf.all.router_solicitations", "expected": 0,
        "severity": "Low", "automatic": True,
        "check_type": "equals",
        "description": "Sets IPv6 router solicitation count to zero.",
        "source": "Ubuntu 22.04 security baseline"
    },
    {
        "id": "UBU-033", "platform": "Ubuntu 22.04",
        "category": "IPv6 Network", "title": "Disable router preference acceptance",
        "setting": "net.ipv6.conf.default.accept_ra_rtr_pref", "expected": 0,
        "severity": "Medium", "automatic": True,
        "check_type": "equals",
        "description": "Disables acceptance of router preference information.",
        "source": "Ubuntu 22.04 security baseline"
    },
    {
        "id": "UBU-034", "platform": "Ubuntu 22.04",
        "category": "IPv6 Network", "title": "Disable prefix information acceptance",
        "setting": "net.ipv6.conf.default.accept_ra_pinfo", "expected": 0,
        "severity": "Medium", "automatic": True,
        "check_type": "equals",
        "description": "Disables acceptance of prefix information from router advertisements.",
        "source": "Ubuntu 22.04 security baseline"
    },
    {
        "id": "UBU-035", "platform": "Ubuntu 22.04",
        "category": "IPv6 Network", "title": "Disable default router advertisement routes",
        "setting": "net.ipv6.conf.default.accept_ra_defrtr", "expected": 0,
        "severity": "Medium", "automatic": True,
        "check_type": "equals",
        "description": "Disables default-router acceptance from advertisements.",
        "source": "Ubuntu 22.04 security baseline"
    },
    {
        "id": "UBU-036", "platform": "Ubuntu 22.04",
        "category": "IPv6 Network", "title": "Disable all router advertisements",
        "setting": "net.ipv6.conf.all.accept_ra", "expected": 0,
        "severity": "High", "automatic": True,
        "check_type": "equals",
        "description": "Disables IPv6 router advertisement acceptance.",
        "source": "Ubuntu 22.04 security baseline"
    },
    {
        "id": "UBU-037", "platform": "Ubuntu 22.04",
        "category": "IPv6 Network", "title": "Disable default router advertisements",
        "setting": "net.ipv6.conf.default.accept_ra", "expected": 0,
        "severity": "High", "automatic": True,
        "check_type": "equals",
        "description": "Disables router advertisement acceptance by default.",
        "source": "Ubuntu 22.04 security baseline"
    },
    {
        "id": "UBU-038", "platform": "Ubuntu 22.04",
        "category": "IPv6 Network", "title": "Disable default IPv6 autoconfiguration",
        "setting": "net.ipv6.conf.default.autoconf", "expected": 0,
        "severity": "Medium", "automatic": True,
        "check_type": "equals",
        "description": "Disables IPv6 address autoconfiguration by default.",
        "source": "Ubuntu 22.04 security baseline"
    },
    {
        "id": "UBU-039", "platform": "Ubuntu 22.04",
        "category": "IPv6 Network", "title": "Disable IPv6 autoconfiguration",
        "setting": "net.ipv6.conf.all.autoconf", "expected": 0,
        "severity": "Medium", "automatic": True,
        "check_type": "equals",
        "description": "Disables IPv6 address autoconfiguration.",
        "source": "Ubuntu 22.04 security baseline"
    },
    {
        "id": "UBU-040", "platform": "Ubuntu 22.04",
        "category": "IPv6 Network", "title": "Disable default DAD transmissions",
        "setting": "net.ipv6.conf.default.dad_transmits", "expected": 0,
        "severity": "Low", "automatic": True,
        "check_type": "equals",
        "description": "Sets default duplicate address detection transmissions to zero.",
        "source": "Ubuntu 22.04 security baseline"
    },
    {
        "id": "UBU-041", "platform": "Ubuntu 22.04",
        "category": "IPv6 Network", "title": "Limit IPv6 addresses",
        "setting": "net.ipv6.conf.default.max_addresses", "expected": 1,
        "severity": "Low", "automatic": True,
        "check_type": "equals",
        "description": "Sets the default maximum number of IPv6 addresses.",
        "source": "Ubuntu 22.04 security baseline"
    },

    # ==========================================
    # C. KERNEL, MEMORY AND PROCESS (12 RULES)
    # ==========================================

    {
        "id": "UBU-042", "platform": "Ubuntu 22.04",
        "category": "Kernel Security", "title": "Restrict kernel module loading",
        "setting": "kernel.modules_disabled", "expected": [0, 1],
        "severity": "High", "automatic": True,
        "check_type": "one_of",
        "description": "Controls whether kernel modules can be loaded. Value 1 locks module loading until reboot; verify the intended policy.",
        "source": "Ubuntu 22.04 security baseline"
    },
    {
        "id": "UBU-043", "platform": "Ubuntu 22.04",
        "category": "Kernel Security", "title": "Disable SysRq",
        "setting": "kernel.sysrq", "expected": 0,
        "severity": "Medium", "automatic": True,
        "check_type": "equals",
        "description": "Disables the kernel Magic SysRq key.",
        "source": "Ubuntu 22.04 security baseline"
    },
    {
        "id": "UBU-044", "platform": "Ubuntu 22.04",
        "category": "Memory Security", "title": "Restrict SUID core dumps",
        "setting": "fs.suid_dumpable", "expected": [0, 2],
        "severity": "High", "automatic": True,
        "check_type": "one_of",
        "description": "Controls core dump behavior for privileged processes.",
        "source": "Ubuntu 22.04 security baseline"
    },
    {
        "id": "UBU-045", "platform": "Ubuntu 22.04",
        "category": "Kernel Security", "title": "Secure kernel core pattern",
        "setting": "kernel.core_pattern", "expected": "%r{^|?/.*}",
        "severity": "Medium", "automatic": True,
        "check_type": "regex",
        "description": "Checks the kernel core dump pattern using the supplied baseline expression. Confirm the expression before enforcement.",
        "source": "Ubuntu 22.04 security baseline"
    },
    {
        "id": "UBU-046", "platform": "Ubuntu 22.04",
        "category": "Memory Security", "title": "Enable address space randomization",
        "setting": "kernel.randomize_va_space", "expected": 2,
        "severity": "High", "automatic": True,
        "check_type": "equals",
        "description": "Enables full address space layout randomization.",
        "source": "Ubuntu 22.04 security baseline"
    },
    {
        "id": "UBU-047", "platform": "Ubuntu 22.04",
        "category": "Memory Security", "title": "Verify NX CPU support",
        "setting": "/proc/cpuinfo", "expected": "nx",
        "severity": "High", "automatic": True,
        "check_type": "contains",
        "description": "Checks whether CPU flags include NX support.",
        "source": "Ubuntu 22.04 security baseline"
    },
    {
        "id": "UBU-048", "platform": "Ubuntu 22.04",
        "category": "Memory Security", "title": "Enable exec-shield",
        "setting": "kernel.exec-shield", "expected": 1,
        "severity": "Medium", "automatic": True,
        "check_type": "equals",
        "description": "Checks the supplied exec-shield setting. This may be unavailable on Ubuntu 22.04.",
        "source": "Ubuntu 22.04 security baseline"
    },
    {
        "id": "UBU-049", "platform": "Ubuntu 22.04",
        "category": "Kernel Security", "title": "Protect FIFO files",
        "setting": "fs.protected_fifos", "expected": [1, 2, None],
        "severity": "Medium", "automatic": True,
        "check_type": "one_of",
        "description": "Checks protection of FIFO files in sticky world-writable directories. Accepted values require confirmation.",
        "source": "Ubuntu 22.04 security baseline"
    },
    {
        "id": "UBU-050", "platform": "Ubuntu 22.04",
        "category": "Kernel Security", "title": "Protect hard links",
        "setting": "fs.protected_hardlinks", "expected": [1, 2, None],
        "severity": "High", "automatic": True,
        "check_type": "one_of",
        "description": "Checks hard-link protection. Accepted values require confirmation.",
        "source": "Ubuntu 22.04 security baseline"
    },
    {
        "id": "UBU-051", "platform": "Ubuntu 22.04",
        "category": "Kernel Security", "title": "Protect regular files",
        "setting": "fs.protected_regular", "expected": 1,
        "severity": "Medium", "automatic": True,
        "check_type": "equals",
        "description": "Checks protection of regular files in sticky world-writable directories.",
        "source": "Ubuntu 22.04 security baseline"
    },
    {
        "id": "UBU-052", "platform": "Ubuntu 22.04",
        "category": "Kernel Security", "title": "Protect symbolic links",
        "setting": "fs.protected_symlinks", "expected": [1, 2],
        "severity": "High", "automatic": True,
        "check_type": "one_of",
        "description": "Checks symbolic-link protection. Accepted values require confirmation.",
        "source": "Ubuntu 22.04 security baseline"
    },
    {
        "id": "UBU-053", "platform": "Ubuntu 22.04",
        "category": "Process Security", "title": "Restrict process tracing",
        "setting": "kernel.yama.ptrace_scope", "expected": None,
        "severity": "High", "automatic": False,
        "check_type": "manual",
        "description": "Restricts process debugging and tracing. The expected value was not specified in the supplied rule list and needs verification.",
        "source": "Ubuntu 22.04 security baseline"
    },
],


"ssh": [
    {
        "id": "SSH-001",
        "platform": "SSH",
        "category": "Cryptography",
        "title": "Approved SSH Ciphers",
        "setting": "Ciphers",
        "expected": "sshd_valid_ciphers",
        "severity": "High",
        "automatic": True,
        "check_type": "custom",
        "description": "Only approved cryptographic ciphers should be enabled.",
        "source": "SSH hardening baseline"
    },
    {
        "id": "SSH-002",
        "platform": "SSH",
        "category": "Cryptography",
        "title": "Approved Key Exchange Algorithms",
        "setting": "KexAlgorithms",
        "expected": "sshd_valid_kexs",
        "severity": "High",
        "automatic": True,
        "check_type": "custom",
        "description": "Only approved key exchange algorithms should be enabled.",
        "source": "SSH hardening baseline"
    },
    {
        "id": "SSH-003",
        "platform": "SSH",
        "category": "Cryptography",
        "title": "Approved MAC Algorithms",
        "setting": "MACs",
        "expected": "sshd_valid_macs",
        "severity": "High",
        "automatic": True,
        "check_type": "custom",
        "description": "Only approved message authentication codes should be enabled.",
        "source": "SSH hardening baseline"
    },
    {
        "id": "SSH-004",
        "platform": "SSH",
        "category": "File Permissions",
        "title": "SSH Custom Configuration Directory Permissions",
        "setting": "sshd_custom_path",
        "expected": "0755",
        "severity": "High",
        "automatic": True,
        "check_type": "file_permission",
        "description": "The custom SSH configuration directory should have restricted permissions and approved ownership.",
        "source": "SSH hardening baseline"
    },
    {
        "id": "SSH-005",
        "platform": "SSH",
        "category": "File Permissions",
        "title": "SSH Configuration File Permissions",
        "setting": "sshd_config",
        "expected": ["0600", "0640"],
        "severity": "High",
        "automatic": True,
        "check_type": "file_permission",
        "description": "The SSH configuration file must not be executable and must have restricted permissions.",
        "source": "SSH hardening baseline"
    },
    {
        "id": "SSH-006",
        "platform": "SSH",
        "category": "Authentication",
        "title": "Root Login Restriction",
        "setting": "PermitRootLogin",
        "expected": ["no", "without-password", "prohibit-password"],
        "severity": "Critical",
        "automatic": True,
        "check_type": "value",
        "description": "Direct root login should be disabled or restricted to public-key authentication.",
        "source": "SSH hardening baseline"
    },
    {
        "id": "SSH-007",
        "platform": "SSH",
        "category": "Network",
        "title": "SSH Port",
        "setting": "Port",
        "expected": "sshd_custom_port",
        "severity": "Medium",
        "automatic": True,
        "check_type": "custom",
        "description": "The SSH port should match the configured approved port.",
        "source": "SSH hardening baseline"
    },
    {
        "id": "SSH-008",
        "platform": "SSH",
        "category": "Network",
        "title": "SSH Address Family",
        "setting": "AddressFamily",
        "expected": ["inet", "inet6", "any"],
        "severity": "Medium",
        "automatic": True,
        "check_type": "value",
        "description": "The SSH address family should match the server's approved network configuration.",
        "source": "SSH hardening baseline"
    },
    {
        "id": "SSH-009",
        "platform": "SSH",
        "category": "Network",
        "title": "SSH Listen Address",
        "setting": "ListenAddress",
        "expected": "not_empty",
        "severity": "Medium",
        "automatic": False,
        "check_type": "manual",
        "description": "SSH should listen only on intended network interfaces.",
        "source": "SSH hardening baseline"
    },
    {
        "id": "SSH-010",
        "platform": "SSH",
        "category": "Protocol",
        "title": "SSH Protocol Version",
        "setting": "Protocol",
        "expected": "2",
        "severity": "High",
        "automatic": True,
        "check_type": "value",
        "description": "Only SSH protocol version 2 should be used. Modern OpenSSH uses version 2 by default.",
        "source": "SSH hardening baseline"
    },
    {
        "id": "SSH-011",
        "platform": "SSH",
        "category": "Authentication",
        "title": "Strict Modes",
        "setting": "StrictModes",
        "expected": "yes",
        "severity": "High",
        "automatic": True,
        "check_type": "value",
        "description": "Strict permission checks should be enabled for user authentication files.",
        "source": "SSH hardening baseline"
    },
    {
        "id": "SSH-012",
        "platform": "SSH",
        "category": "Logging",
        "title": "Syslog Facility",
        "setting": "SyslogFacility",
        "expected": ["AUTH", "AUTHPRIV"],
        "severity": "Medium",
        "automatic": True,
        "check_type": "value",
        "description": "SSH authentication events should use an approved logging facility.",
        "source": "SSH hardening baseline"
    },
    {
        "id": "SSH-013",
        "platform": "SSH",
        "category": "Logging",
        "title": "SSH Log Level",
        "setting": "LogLevel",
        "expected": "VERBOSE",
        "severity": "Medium",
        "automatic": True,
        "check_type": "value",
        "description": "Verbose logging should be enabled to improve authentication auditing.",
        "source": "SSH hardening baseline"
    },
    {
        "id": "SSH-014",
        "platform": "SSH",
        "category": "Cryptography",
        "title": "Approved Host Keys",
        "setting": "HostKey",
        "expected": "sshd_valid_hostkeys",
        "severity": "High",
        "automatic": True,
        "check_type": "custom",
        "description": "Only approved SSH host key types and locations should be configured.",
        "source": "SSH hardening baseline"
    },
    {
        "id": "SSH-015",
        "platform": "SSH",
        "category": "Authentication",
        "title": "UseLogin",
        "setting": "UseLogin",
        "expected": "no",
        "severity": "Medium",
        "automatic": False,
        "check_type": "manual",
        "description": "Verify that the deprecated UseLogin option is not enabled.",
        "source": "SSH hardening baseline"
    },
    {
        "id": "SSH-016",
        "platform": "SSH",
        "category": "Authentication",
        "title": "UsePrivilegeSeparation",
        "setting": "UsePrivilegeSeparation",
        "expected": "sshd_valid_privseparation",
        "severity": "Medium",
        "automatic": False,
        "check_type": "manual",
        "description": "This option is removed in modern OpenSSH. Verify the installed OpenSSH version and applicable security architecture.",
        "source": "SSH hardening baseline"
    },
    {
        "id": "SSH-017",
        "platform": "SSH",
        "category": "Authentication",
        "title": "Permit User Environment",
        "setting": "PermitUserEnvironment",
        "expected": "no",
        "severity": "High",
        "automatic": True,
        "check_type": "value",
        "description": "Users should not be allowed to introduce environment variables through SSH configuration files.",
        "source": "SSH hardening baseline"
    },
    {
        "id": "SSH-018",
        "platform": "SSH",
        "category": "Authentication",
        "title": "Login Grace Time",
        "setting": "LoginGraceTime",
        "expected": "30s",
        "severity": "Medium",
        "automatic": True,
        "check_type": "value",
        "description": "Limit the time allowed for completing SSH authentication.",
        "source": "SSH hardening baseline"
    },
    {
        "id": "SSH-019",
        "platform": "SSH",
        "category": "Authentication",
        "title": "Maximum Authentication Attempts",
        "setting": "MaxAuthTries",
        "expected": "sshd_max_auth_tries",
        "severity": "High",
        "automatic": True,
        "check_type": "custom",
        "description": "Limit the number of authentication attempts per connection.",
        "source": "SSH hardening baseline"
    },
    {
        "id": "SSH-020",
        "platform": "SSH",
        "category": "Authentication",
        "title": "Maximum SSH Sessions",
        "setting": "MaxSessions",
        "expected": "10",
        "severity": "Medium",
        "automatic": True,
        "check_type": "value",
        "description": "Limit the number of multiplexed sessions per network connection.",
        "source": "SSH hardening baseline"
    },
    {
        "id": "SSH-021",
        "platform": "SSH",
        "category": "Authentication",
        "title": "Maximum Concurrent Unauthenticated Connections",
        "setting": "MaxStartups",
        "expected": "10:30:60",
        "severity": "High",
        "automatic": True,
        "check_type": "value",
        "description": "Limit concurrent unauthenticated SSH connections.",
        "source": "SSH hardening baseline"
    },
    {
        "id": "SSH-022",
        "platform": "SSH",
        "category": "Authentication",
        "title": "Public Key Authentication",
        "setting": "PubkeyAuthentication",
        "expected": "yes",
        "severity": "High",
        "automatic": True,
        "check_type": "value",
        "description": "Enable public key authentication.",
        "source": "SSH hardening baseline"
    },
    {
        "id": "SSH-023",
        "platform": "SSH",
        "category": "Authentication",
        "title": "Ignore Rhosts",
        "setting": "IgnoreRhosts",
        "expected": "yes",
        "severity": "High",
        "automatic": True,
        "check_type": "value",
        "description": "Ignore legacy rhosts-based authentication files.",
        "source": "SSH hardening baseline"
    },
    {
        "id": "SSH-024",
        "platform": "SSH",
        "category": "Authentication",
        "title": "Ignore User Known Hosts",
        "setting": "IgnoreUserKnownHosts",
        "expected": "yes",
        "severity": "Medium",
        "automatic": True,
        "check_type": "value",
        "description": "Do not use user-controlled known_hosts files for host-based authentication.",
        "source": "SSH hardening baseline"
    },
    {
        "id": "SSH-025",
        "platform": "SSH",
        "category": "Authentication",
        "title": "Host Based Authentication",
        "setting": "HostbasedAuthentication",
        "expected": "no",
        "severity": "High",
        "automatic": True,
        "check_type": "value",
        "description": "Disable host-based authentication.",
        "source": "SSH hardening baseline"
    },
    {
        "id": "SSH-026",
        "platform": "SSH",
        "category": "Authentication",
        "title": "Password Authentication",
        "setting": "PasswordAuthentication",
        "expected": "no",
        "severity": "High",
        "automatic": True,
        "check_type": "value",
        "description": "Disable password-based SSH authentication where key-based authentication is used.",
        "source": "SSH hardening baseline"
    },
    {
        "id": "SSH-027",
        "platform": "SSH",
        "category": "Authentication",
        "title": "Permit Empty Passwords",
        "setting": "PermitEmptyPasswords",
        "expected": "no",
        "severity": "Critical",
        "automatic": True,
        "check_type": "value",
        "description": "Do not permit accounts with empty passwords to authenticate over SSH.",
        "source": "SSH hardening baseline"
    },
    {
        "id": "SSH-028",
        "platform": "SSH",
        "category": "Authentication",
        "title": "Challenge Response Authentication",
        "setting": "ChallengeResponseAuthentication",
        "expected": "no",
        "severity": "High",
        "automatic": False,
        "check_type": "manual",
        "description": "Verify the effective keyboard-interactive authentication setting. This option is a legacy alias in modern OpenSSH.",
        "source": "SSH hardening baseline"
    },
    {
        "id": "SSH-029",
        "platform": "SSH",
        "category": "Authentication",
        "title": "Kerberos Authentication",
        "setting": "KerberosAuthentication",
        "expected": "no",
        "severity": "Medium",
        "automatic": True,
        "check_type": "value",
        "description": "Disable Kerberos authentication unless explicitly required.",
        "source": "SSH hardening baseline"
    },
    {
        "id": "SSH-030",
        "platform": "SSH",
        "category": "Authentication",
        "title": "Kerberos Or Local Password",
        "setting": "KerberosOrLocalPasswd",
        "expected": "no",
        "severity": "Medium",
        "automatic": False,
        "check_type": "manual",
        "description": "Verify this legacy Kerberos option where supported by the installed OpenSSH version.",
        "source": "SSH hardening baseline"
    },
    {
        "id": "SSH-031",
        "platform": "SSH",
        "category": "Authentication",
        "title": "Kerberos Ticket Cleanup",
        "setting": "KerberosTicketCleanup",
        "expected": "yes",
        "severity": "Low",
        "automatic": False,
        "check_type": "manual",
        "description": "Verify Kerberos ticket cleanup behavior if Kerberos authentication is in use.",
        "source": "SSH hardening baseline"
    },
    {
        "id": "SSH-032",
        "platform": "SSH",
        "category": "Authentication",
        "title": "GSSAPI Authentication",
        "setting": "GSSAPIAuthentication",
        "expected": "no",
        "severity": "Medium",
        "automatic": True,
        "check_type": "value",
        "description": "Disable GSSAPI authentication unless required by the environment.",
        "source": "SSH hardening baseline"
    },
    {
        "id": "SSH-033",
        "platform": "SSH",
        "category": "Authentication",
        "title": "GSSAPI Credential Cleanup",
        "setting": "GSSAPICleanupCredentials",
        "expected": "yes",
        "severity": "Low",
        "automatic": False,
        "check_type": "manual",
        "description": "Verify that GSSAPI credentials are cleaned up when GSSAPI is used.",
        "source": "SSH hardening baseline"
    },
    {
        "id": "SSH-034",
        "platform": "SSH",
        "category": "Network",
        "title": "TCP Keep Alive",
        "setting": "TCPKeepAlive",
        "expected": "no",
        "severity": "Medium",
        "automatic": True,
        "check_type": "value",
        "description": "Apply the TCP keep-alive policy selected for this server.",
        "source": "SSH hardening baseline"
    },
    {
        "id": "SSH-035",
        "platform": "SSH",
        "category": "Network",
        "title": "Client Alive Interval",
        "setting": "ClientAliveInterval",
        "expected": "300",
        "severity": "Medium",
        "automatic": True,
        "check_type": "value",
        "description": "Set the interval for client inactivity checks.",
        "source": "SSH hardening baseline"
    },
    {
        "id": "SSH-036",
        "platform": "SSH",
        "category": "Network",
        "title": "Client Alive Count Maximum",
        "setting": "ClientAliveCountMax",
        "expected": "3",
        "severity": "Medium",
        "automatic": True,
        "check_type": "value",
        "description": "Limit unanswered client alive messages before disconnecting.",
        "source": "SSH hardening baseline"
    },
    {
        "id": "SSH-037",
        "platform": "SSH",
        "category": "Network",
        "title": "Permit Tunnel",
        "setting": "PermitTunnel",
        "expected": "no",
        "severity": "Medium",
        "automatic": True,
        "check_type": "value",
        "description": "Disable SSH tunneling unless explicitly required.",
        "source": "SSH hardening baseline"
    },
    {
        "id": "SSH-038",
        "platform": "SSH",
        "category": "Network",
        "title": "Allow TCP Forwarding",
        "setting": "AllowTcpForwarding",
        "expected": "no",
        "severity": "High",
        "automatic": True,
        "check_type": "value",
        "description": "Disable TCP forwarding unless required by the server role.",
        "source": "SSH hardening baseline"
    },
    {
        "id": "SSH-039",
        "platform": "SSH",
        "category": "Network",
        "title": "Allow Agent Forwarding",
        "setting": "AllowAgentForwarding",
        "expected": "no",
        "severity": "Medium",
        "automatic": True,
        "check_type": "value",
        "description": "Disable SSH agent forwarding unless required.",
        "source": "SSH hardening baseline"
    },
    {
        "id": "SSH-040",
        "platform": "SSH",
        "category": "Network",
        "title": "Gateway Ports",
        "setting": "GatewayPorts",
        "expected": "no",
        "severity": "High",
        "automatic": True,
        "check_type": "value",
        "description": "Prevent remote hosts from connecting to forwarded ports by default.",
        "source": "SSH hardening baseline"
    },
    {
        "id": "SSH-041",
        "platform": "SSH",
        "category": "Network",
        "title": "X11 Forwarding",
        "setting": "X11Forwarding",
        "expected": "no",
        "severity": "Medium",
        "automatic": True,
        "check_type": "value",
        "description": "Disable X11 forwarding unless explicitly required.",
        "source": "SSH hardening baseline"
    },
    {
        "id": "SSH-042",
        "platform": "SSH",
        "category": "Network",
        "title": "X11 Use Localhost",
        "setting": "X11UseLocalhost",
        "expected": "yes",
        "severity": "Medium",
        "automatic": True,
        "check_type": "value",
        "description": "Bind X11 forwarding to the loopback address.",
        "source": "SSH hardening baseline"
    },
    {
        "id": "SSH-043",
        "platform": "SSH",
        "category": "Logging",
        "title": "Print Message Of The Day",
        "setting": "PrintMotd",
        "expected": "no",
        "severity": "Low",
        "automatic": True,
        "check_type": "value",
        "description": "Disable the SSH daemon's built-in message of the day display.",
        "source": "SSH hardening baseline"
    },
    {
        "id": "SSH-044",
        "platform": "SSH",
        "category": "Logging",
        "title": "Print Last Login",
        "setting": "PrintLastLog",
        "expected": "no",
        "severity": "Low",
        "automatic": True,
        "check_type": "value",
        "description": "Apply the configured last-login display policy.",
        "source": "SSH hardening baseline"
    },
    {
        "id": "SSH-045",
        "platform": "SSH",
        "category": "Logging",
        "title": "SSH Banner",
        "setting": "Banner",
        "expected": "sshd_banner",
        "severity": "Medium",
        "automatic": False,
        "check_type": "manual",
        "description": "Verify that the configured login banner meets the organization's policy.",
        "source": "SSH hardening baseline"
    },
    {
        "id": "SSH-046",
        "platform": "SSH",
        "category": "Logging",
        "title": "Debian Banner",
        "setting": "DebianBanner",
        "expected": "no",
        "severity": "Low",
        "automatic": True,
        "check_type": "value",
        "description": "Disable the default Debian SSH version banner where supported.",
        "source": "SSH hardening baseline"
    },
    {
        "id": "SSH-047",
        "platform": "SSH",
        "category": "Cryptography",
        "title": "SSH Moduli Prime Size",
        "setting": "moduli_prime_size",
        "expected": ">=2048",
        "severity": "High",
        "automatic": False,
        "check_type": "manual",
        "description": "Verify that configured Diffie-Hellman moduli meet the minimum prime size requirement.",
        "source": "SSH hardening baseline"
    },
    {
        "id": "SSH-048",
        "platform": "SSH",
        "category": "Process Security",
        "title": "SSH Daemon Command Line Overrides",
        "setting": "sshd_process_arguments",
        "expected": "no_cli_overrides",
        "severity": "High",
        "automatic": False,
        "check_type": "manual",
        "description": "Verify that the running SSH daemon has no command-line configuration overrides.",
        "source": "SSH hardening baseline"
    },
    {
        "id": "SSH-049",
        "platform": "SSH",
        "category": "Cryptography",
        "title": "RSA Host Key Size",
        "setting": "ssh_host_rsa_key",
        "expected": ">=4096",
        "severity": "High",
        "automatic": False,
        "check_type": "manual",
        "description": "Verify that the RSA SSH host key is at least 4096 bits.",
        "source": "SSH hardening baseline"
    },
],




"nginx": [
    {
        "id": "NGX-001",
        "platform": "NGINX",
        "category": "Information Disclosure",
        "title": "Hide NGINX Version Information",
        "setting": "server_tokens",
        "expected": "off",
        "severity": "Medium",
        "automatic": True,
        "check_type": "value",
        "description": "Verify that server_tokens is configured as off to prevent disclosure of NGINX version information.",
        "source": "NGINX CIS Benchmark 2.5"
    },
    {
        "id": "NGX-002",
        "platform": "NGINX",
        "category": "Error Handling",
        "title": "Custom Error Pages",
        "setting": "error_page",
        "expected": "custom_error_pages",
        "severity": "Low",
        "automatic": False,
        "check_type": "manual",
        "description": "Verify that custom error pages do not expose default NGINX branding or unnecessary server information.",
        "source": "NGINX CIS Benchmark 2.5"
    },
    {
        "id": "NGX-003",
        "platform": "NGINX",
        "category": "Access Control",
        "title": "Restrict Access to Hidden Files",
        "setting": "location ~ /\\.",
        "expected": ["deny all", "return 404"],
        "severity": "High",
        "automatic": False,
        "check_type": "manual",
        "description": "Verify that requests for hidden files and directories are denied or return a 404 response.",
        "source": "NGINX CIS Benchmark 2.5"
    },
    {
        "id": "NGX-004",
        "platform": "NGINX",
        "category": "Information Disclosure",
        "title": "Hide Upstream Server Headers",
        "setting": "proxy_hide_header / fastcgi_hide_header",
        "expected": ["X-Powered-By", "Server"],
        "severity": "Medium",
        "automatic": False,
        "check_type": "manual",
        "description": "Verify that sensitive upstream technology headers such as X-Powered-By and Server are hidden where applicable.",
        "source": "NGINX CIS Benchmark 2.5"
    },
],

}


def get_all_rules():
    """Return all standard security rules."""
    return [
        rule
        for rules in STANDARD_SECURITY_BASELINE.values()
        for rule in rules
    ]


def get_automatic_rules():
    """Return rules that can be checked automatically."""
    return [
        rule for rule in get_all_rules()
        if rule["automatic"] is True
    ]


def get_manual_rules():
    """Return rules requiring manual verification."""
    return [
        rule for rule in get_all_rules()
        if rule["automatic"] is False
    ]



def validate_baseline():
    """Validate rule structure, IDs, severity and check types."""

    rules = get_all_rules()
    rule_ids = [rule["id"] for rule in rules]

    # Check duplicate IDs
    if len(rule_ids) != len(set(rule_ids)):
        raise ValueError("Duplicate security rule IDs found.")

    required_fields = set(RULE_TEMPLATE.keys())

    valid_severities = {"Critical", "High", "Medium", "Low"}

    valid_check_types = {
    "contains",
    "custom",
    "equals",
    "file_permission",
    "manual",
    "not_empty",
    "one_of",
    "regex",
    "value",
}

    for rule in rules:

        # Check required fields
        missing = required_fields - rule.keys()

        if missing:
            raise ValueError(
                f"Rule {rule.get('id')} is missing: {missing}"
            )

        # Check required text fields
        text_fields = [
            "id", "platform", "category", "title",
            "setting", "check_type", "description", "source"
        ]

        for field in text_fields:
            if not isinstance(rule[field], str) or not rule[field].strip():
                raise ValueError(
                    f"Invalid or empty {field} in rule {rule['id']}"
                )

        # Check severity
        if rule["severity"] not in valid_severities:
            raise ValueError(
                f"Invalid severity in rule {rule['id']}"
            )

        # Check automatic status
        if not isinstance(rule["automatic"], bool):
            raise ValueError(
                f"Invalid automatic status: {rule['id']}"
            )

        # Check check_type
        if rule["check_type"] not in valid_check_types:
            raise ValueError(
                f"Invalid check_type in rule {rule['id']}"
            )

        # Automatic rules must have an expected value
        if rule["automatic"] and rule["expected"] is None:
            raise ValueError(
                f"Automatic rule has no expected value: {rule['id']}"
            )

        # Manual rules must use the manual check type
        if not rule["automatic"] and rule["check_type"] != "manual":
            raise ValueError(
                f"Manual rule has incorrect check_type: {rule['id']}"
            )

        # Automatic rules cannot use manual check type
        if rule["automatic"] and rule["check_type"] == "manual":
            raise ValueError(
                f"Automatic rule uses manual check_type: {rule['id']}"
            )

    return {
        "total": len(rules),
        "automatic": len(get_automatic_rules()),
        "manual": len(get_manual_rules()),
    }
