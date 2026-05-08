"""
passive traffic analysis for attack-relevant protocol disclosures.
sniffs on the victim interface and flags provisioning, discovery,
and management traffic that's useful for targeting.
"""

import logging
import threading
from collections import defaultdict

from scapy.all import (
    AsyncSniffer, PcapWriter,
    Ether, IP, UDP, TCP, DNS, DNSQR, Raw,
    DHCP,
)
from socket import inet_aton

# community/contrib layers
from scapy.contrib.cdp import CDPv2_HDR, CDPMsgDeviceID, CDPMsgPlatform, CDPMsgAddr, CDPMsgPortID
from scapy.contrib.lldp import (
    LLDPDU, LLDPDUSystemName, LLDPDUSystemDescription,
    LLDPDUManagementAddress, LLDPDUPortDescription,
)

log = logging.getLogger('recon')

# terminal colors
C = '\033[36m'   # cyan  - URLs, actionable data
G = '\033[32m'   # green - IPs
Y = '\033[33m'   # yellow - vendor/category
B = '\033[1m'    # bold
RST = '\033[0m'

# ─── signature database ────────────────────────────────────────────

SIGNATURES = {
    'polycom': {
        'dns_patterns': ['polycom', 'poly.com', 'plcm.net'],
        'dhcp_options': [66, 160],
        'http_paths': ['/000000000000.cfg', '/phone1.cfg', '/Config/'],
    },
    'cisco': {
        'dns_patterns': ['cisco', 'webex'],
        'dhcp_options': [150],
        'http_paths': ['/SEP', '.cnf.xml', '/XMLDefault.cnf.xml'],
    },
    'yealink': {
        'dns_patterns': ['yealink', 'rps.yealink.com'],
        'dhcp_options': [66],
        'http_paths': ['/y0000000000', '/autoprovision.cfg'],
    },
    'grandstream': {
        'dns_patterns': ['grandstream', 'gs.grandstream.com'],
        'dhcp_options': [66],
        'http_paths': ['/cfg', '/gs_config'],
    },
    'snom': {
        'dns_patterns': ['snom'],
        'dhcp_options': [66],
        'http_paths': ['/snom', '/snom.htm'],
    },
    'audiocodes': {
        'dns_patterns': ['audiocodes', 'audiocodes.com'],
        'dhcp_options': [66, 160],
        'http_paths': ['/config', '/audiocodes'],
    },
    'mitel': {
        'dns_patterns': ['mitel', 'shoretel'],
        'dhcp_options': [66, 156, 157],
        'http_paths': ['/MN_', '/MiVoice'],
    },
    'ubiquiti': {
        'dns_patterns': ['ubnt', 'ui.com', 'unifi'],
        'dhcp_options': [66],
        'http_paths': ['/inform', '/dl/firmware'],
    },
}

# DHCP options that are interesting even without a vendor match
INTERESTING_DHCP_OPTS = {
    66: 'TFTP Server',
    67: 'Boot File',
    150: 'TFTP Server (Cisco)',
    160: 'Provisioning URL (Polycom)',
    161: 'Provisioning URL',
    162: 'Provisioning URL (proxy)',
}


class ReconEngine:
    def __init__(self, iface, pcap_path=None, pool_range=None):
        self.iface = iface
        self.pcap_path = pcap_path
        self.pool_range = pool_range  # (start_ip, end_ip) as ints
        self._sniffer = None
        self._writer = None
        self._writer_lock = threading.Lock()
        self._stop = threading.Event()
        self._seen = set()
        self.findings = defaultdict(list)

    def start(self):
        if self.pcap_path:
            self._writer = PcapWriter(self.pcap_path, append=True, sync=True)

        self._sniffer = AsyncSniffer(
            iface=self.iface,
            prn=self._on_packet,
            store=False,
        )
        self._sniffer.start()
        log.info(f'recon listening on {self.iface}')

    def stop(self):
        self._stop.set()
        if self._sniffer and self._sniffer.running:
            self._sniffer.stop()
        if self._writer:
            self._writer.close()

    def reset(self):
        self._seen.clear()
        self.findings.clear()
        if self._writer:
            self._writer.close()
        if self.pcap_path:
            self._writer = PcapWriter(self.pcap_path, append=False, sync=True)

    def _is_victim_traffic(self, pkt):
        if not self.pool_range:
            return True
        if not pkt.haslayer(IP):
            return True  # non-IP (ARP, LLDP, CDP) always passes
        lo, hi = self.pool_range
        src = int.from_bytes(inet_aton(pkt[IP].src), 'big')
        dst = int.from_bytes(inet_aton(pkt[IP].dst), 'big')
        return (lo <= src <= hi) or (lo <= dst <= hi)

    def _on_packet(self, pkt):
        if not self._is_victim_traffic(pkt):
            return

        if self._writer:
            with self._writer_lock:
                self._writer.write(pkt)

        if pkt.haslayer(CDPv2_HDR):
            self._handle_cdp(pkt)
        if pkt.haslayer(LLDPDU):
            self._handle_lldp(pkt)
        if pkt.haslayer(DHCP):
            self._handle_dhcp(pkt)
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            self._handle_dns(pkt)
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            self._handle_http(pkt)
            self._handle_tls_sni(pkt)
        if pkt.haslayer(UDP) and pkt.haslayer(Raw) and not pkt.haslayer(DNS):
            self._handle_sip(pkt)

    def _handle_cdp(self, pkt):
        info = {}
        if pkt.haslayer(CDPMsgDeviceID):
            info['device_id'] = pkt[CDPMsgDeviceID].val.decode(errors='replace')
        if pkt.haslayer(CDPMsgPlatform):
            info['platform'] = pkt[CDPMsgPlatform].val.decode(errors='replace')
        if pkt.haslayer(CDPMsgPortID):
            info['port'] = pkt[CDPMsgPortID].iface.decode(errors='replace')
        if pkt.haslayer(CDPMsgAddr):
            try:
                info['address'] = pkt[CDPMsgAddr].addr
            except Exception:
                pass

        if info:
            self._flag('CDP', info)

    def _handle_lldp(self, pkt):
        info = {}
        if pkt.haslayer(LLDPDUSystemName):
            info['system_name'] = pkt[LLDPDUSystemName].system_name.decode(errors='replace')
        if pkt.haslayer(LLDPDUSystemDescription):
            info['description'] = pkt[LLDPDUSystemDescription].description.decode(errors='replace')
        if pkt.haslayer(LLDPDUPortDescription):
            info['port'] = pkt[LLDPDUPortDescription].description.decode(errors='replace')
        if pkt.haslayer(LLDPDUManagementAddress):
            try:
                info['mgmt_addr'] = pkt[LLDPDUManagementAddress].management_address
            except Exception:
                pass

        if info:
            self._flag('LLDP', info)

    def _handle_dhcp(self, pkt):
        opts = {opt[0]: opt[1:] for opt in pkt[DHCP].options
                if isinstance(opt, tuple) and len(opt) >= 2}

        # vendor class ID is a direct device fingerprint
        vendor_class = opts.get('vendor_class_id')
        if vendor_class:
            val = vendor_class[0]
            if isinstance(val, bytes):
                val = val.decode(errors='replace')
            self._flag('DHCP Fingerprint', {'vendor_class': val})

        # param_req_list tells us what provisioning the device expects
        req_list = opts.get('param_req_list')
        if req_list:
            requested = req_list[0] if isinstance(req_list[0], list) else [req_list[0]]
            interesting = [(r, INTERESTING_DHCP_OPTS[r]) for r in requested
                           if r in INTERESTING_DHCP_OPTS]
            if interesting:
                labels = [f'{name} ({code})' for code, name in interesting]
                self._flag('DHCP Request', {
                    'requesting': ', '.join(labels),
                })

        # flag provisioning options the server handed back
        for opt in pkt[DHCP].options:
            if isinstance(opt, tuple) and len(opt) >= 2:
                code = opt[0] if isinstance(opt[0], int) else None
                if code and code in INTERESTING_DHCP_OPTS:
                    self._flag('DHCP Option', {
                        'option': code,
                        'name': INTERESTING_DHCP_OPTS[code],
                        'value': opt[1],
                    })

    def _handle_dns(self, pkt):
        # only queries (qr=0), not responses
        if pkt[DNS].qr != 0:
            return

        qname = pkt[DNSQR].qname.decode(errors='replace').rstrip('.')
        qname_lower = qname.lower()

        for vendor, sigs in SIGNATURES.items():
            for pattern in sigs.get('dns_patterns', []):
                if pattern in qname_lower:
                    self._flag('DNS (vendor match)', {
                        'vendor': vendor,
                        'query': qname,
                        'src': pkt[IP].src if pkt.haslayer(IP) else '?',
                    })
                    return

    def _handle_http(self, pkt):
        try:
            payload = pkt[Raw].load.decode(errors='replace')
        except Exception:
            return

        if not payload.startswith(('GET ', 'POST ', 'PUT ')):
            return

        lines = payload.split('\r\n')
        first_line = lines[0]
        path = first_line.split(' ')[1] if ' ' in first_line else ''

        host = None
        for line in lines[1:]:
            if line.lower().startswith('host:'):
                host = line.split(':', 1)[1].strip()
                break

        dst = pkt[IP].dst if pkt.haslayer(IP) else None
        base = f'http://{host}' if host else f'http://{dst}' if dst else 'http://?'
        full_url = base + path

        for vendor, sigs in SIGNATURES.items():
            for pattern in sigs.get('http_paths', []):
                if pattern.lower() in path.lower():
                    self._flag('HTTP Provisioning', {
                        'vendor': vendor,
                        'url': full_url,
                        'src': pkt[IP].src if pkt.haslayer(IP) else '?',
                    })
                    return

    def _handle_sip(self, pkt):
        try:
            payload = pkt[Raw].load.decode(errors='replace')
        except Exception:
            return

        if 'REGISTER sip:' in payload or 'INVITE sip:' in payload:
            first_line = payload.split('\r\n', 1)[0]
            self._flag('SIP', {
                'method': first_line,
                'src': pkt[IP].src if pkt.haslayer(IP) else '?',
            })

    def _handle_tls_sni(self, pkt):
        try:
            payload = bytes(pkt[Raw].load)
        except Exception:
            return

        # TLS record: content_type=22 (handshake), then version, length
        if len(payload) < 6 or payload[0] != 0x16:
            return
        # handshake type=1 (ClientHello) at offset 5
        if payload[5] != 0x01:
            return

        # walk the extensions to find SNI (type 0x0000)
        try:
            sni = self._extract_sni(payload)
        except Exception:
            return

        if sni:
            self._flag('TLS SNI', {
                'server': sni,
                'dst': pkt[IP].dst if pkt.haslayer(IP) else '?',
                'src': pkt[IP].src if pkt.haslayer(IP) else '?',
            })

    def _extract_sni(self, data):
        # skip TLS record header (5) + handshake header (4)
        # + client version (2) + random (32) = offset 43
        if len(data) < 44:
            return None
        offset = 43

        # session ID
        sid_len = data[offset]
        offset += 1 + sid_len

        # cipher suites
        if offset + 2 > len(data):
            return None
        cs_len = int.from_bytes(data[offset:offset+2], 'big')
        offset += 2 + cs_len

        # compression methods
        if offset + 1 > len(data):
            return None
        cm_len = data[offset]
        offset += 1 + cm_len

        # extensions length
        if offset + 2 > len(data):
            return None
        ext_len = int.from_bytes(data[offset:offset+2], 'big')
        offset += 2

        end = offset + ext_len
        while offset + 4 <= end:
            ext_type = int.from_bytes(data[offset:offset+2], 'big')
            ext_size = int.from_bytes(data[offset+2:offset+4], 'big')
            offset += 4

            if ext_type == 0:  # SNI
                # SNI list length (2) + type (1) + name length (2)
                if offset + 5 > len(data):
                    return None
                name_len = int.from_bytes(data[offset+3:offset+5], 'big')
                if offset + 5 + name_len > len(data):
                    return None
                return data[offset+5:offset+5+name_len].decode('ascii', errors='replace')

            offset += ext_size

        return None

    def _flag(self, category, details):
        # deduplicate repeated findings (LLDP/CDP fire every few seconds)
        key = (category, tuple(sorted(details.items())))
        if key in self._seen:
            return
        self._seen.add(key)

        self.findings[category].append(details)

        parts = []
        for k, v in details.items():
            vs = str(v)
            if k in ('src', 'dst', 'address', 'mgmt_addr'):
                parts.append(f'{k}={G}{vs}{RST}')
            elif k in ('url', 'path', 'query', 'method', 'server',
                        'vendor_class', 'requesting'):
                parts.append(f'{k}={C}{vs}{RST}')
            else:
                parts.append(f'{k}={vs}')

        detail_str = ', '.join(parts)
        print(f'  {Y}[!]{RST} {B}{category}{RST}: {detail_str}')
