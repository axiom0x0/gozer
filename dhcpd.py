"""
bare-bones DHCP server. handles DISCOVER/OFFER/REQUEST/ACK and not
much else. lease expiry is tracked but not enforced (good enough for
a MitM scenario where clients are transient anyway).
"""

import time
import socket
import struct
import logging
import threading


SERVER_PORT = 67
CLIENT_PORT = 68
MAGIC = b'\x63\x82\x53\x63'

# message types
DISCOVER, OFFER, REQUEST, DECLINE, ACK, NAK, RELEASE = range(1, 8)

# options we actually use
OPT_SUBNET    = 1
OPT_ROUTER    = 3
OPT_DNS       = 6
OPT_LEASE     = 51
OPT_MSG_TYPE  = 53
OPT_SERVER_ID = 54
OPT_END       = 255

# fixed header: op(1) htype(1) hlen(1) hops(1) xid(4) secs(2) flags(2)
#               ciaddr(4) yiaddr(4) siaddr(4) giaddr(4) chaddr(16)
#               sname(64) file(128)
HDR_FMT = '!BBBB4sHH4s4s4s4s16s64s128s'
HDR_LEN = struct.calcsize(HDR_FMT)


class Lease:
    __slots__ = ('mac', 'ip', 'expires')

    def __init__(self, mac, ip, expires):
        self.mac = mac
        self.ip = ip
        self.expires = expires


class DHCPServer:
    def __init__(self, iface, server_ip, subnet, pool_start, pool_end,
                 router=None, dns=None, lease_time=3600, extra_opts=None):
        self.iface = iface
        self.server_ip = server_ip
        self.subnet = subnet
        self.pool_start = pool_start
        self.pool_end = pool_end
        self.router = router or server_ip
        self.dns = dns or '8.8.8.8'
        self.lease_time = lease_time
        self.extra_opts = extra_opts or {}
        self.leases = {}  # mac -> Lease
        self.sock = None
        self._stop = threading.Event()
        self.log = logging.getLogger('dhcpd')

    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # SO_BINDTODEVICE = 25 on linux
        self.sock.setsockopt(socket.SOL_SOCKET, 25,
                             self.iface.encode() + b'\0')
        self.sock.settimeout(1.0)
        self.sock.bind(('0.0.0.0', SERVER_PORT))
        self.log.info(f'dhcp listening on {self.iface}')

        while not self._stop.is_set():
            try:
                data, addr = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            self._handle(data)

    def stop(self):
        self._stop.set()
        if self.sock:
            self.sock.close()

    def _handle(self, data):
        if len(data) < HDR_LEN + 4:
            return

        hdr = struct.unpack(HDR_FMT, data[:HDR_LEN])
        op = hdr[0]
        hlen = hdr[2]
        xid = hdr[4]
        chaddr = hdr[11]

        if op != 1:
            return

        mac = ':'.join(f'{b:02x}' for b in chaddr[:hlen])
        # self.log.debug(f'raw from {mac}: {data[:HDR_LEN].hex()}')

        if data[HDR_LEN:HDR_LEN + 4] != MAGIC:
            return

        options = _parse_opts(data[HDR_LEN + 4:])
        raw_type = options.get(OPT_MSG_TYPE)
        if not raw_type:
            return
        msg_type = raw_type[0]

        if msg_type == DISCOVER:
            self.log.info(f'DISCOVER from {mac}')
            ip = self._allocate(mac)
            if ip:
                self._send(OFFER, xid, chaddr, hlen, ip)
        elif msg_type == REQUEST:
            ip = self._allocate(mac)
            if ip:
                self._send(ACK, xid, chaddr, hlen, ip)
                self.log.info(f'ACK {ip} -> {mac}')
        elif msg_type == RELEASE:
            self.log.info(f'RELEASE from {mac}')
            self.leases.pop(mac, None)

    def _allocate(self, mac):
        """same MAC always gets the same lease back."""
        if mac in self.leases:
            self.leases[mac].expires = time.time() + self.lease_time
            return self.leases[mac].ip

        # TODO: expire stale leases so the pool doesn't just fill up
        used = {l.ip for l in self.leases.values()}
        lo = int.from_bytes(socket.inet_aton(self.pool_start), 'big')
        hi = int.from_bytes(socket.inet_aton(self.pool_end), 'big')

        for n in range(lo, hi + 1):
            candidate = socket.inet_ntoa(n.to_bytes(4, 'big'))
            if candidate not in used:
                self.leases[mac] = Lease(mac, candidate,
                                         time.time() + self.lease_time)
                return candidate

        self.log.warning('address pool exhausted')
        return None

    def _send(self, msg_type, xid, chaddr, hlen, yiaddr):
        pkt = self._build(msg_type, xid, chaddr, hlen, yiaddr)
        self.sock.sendto(pkt, ('255.255.255.255', CLIENT_PORT))

    def _build(self, msg_type, xid, chaddr, hlen, yiaddr):
        hdr = struct.pack(
            HDR_FMT,
            2, 1, hlen, 0,                      # op, htype, hlen, hops
            xid, 0, 0,                           # xid, secs, flags
            b'\x00' * 4,                         # ciaddr
            socket.inet_aton(yiaddr),            # yiaddr
            socket.inet_aton(self.server_ip),    # siaddr
            b'\x00' * 4,                         # giaddr
            chaddr,                              # chaddr
            b'\x00' * 64,                        # sname
            b'\x00' * 128,                       # file
        )

        # defaults, then let extra_opts override any of them
        defaults = {
            OPT_MSG_TYPE:  bytes([msg_type]),
            OPT_SERVER_ID: socket.inet_aton(self.server_ip),
            OPT_LEASE:     struct.pack('!I', self.lease_time),
            OPT_SUBNET:    socket.inet_aton(str(self.subnet.netmask)),
            OPT_ROUTER:    socket.inet_aton(self.router),
            OPT_DNS:       socket.inet_aton(self.dns),
        }
        for code, val in self.extra_opts.items():
            defaults[code] = val if isinstance(val, bytes) else val.encode()

        opts = MAGIC
        for code, val in defaults.items():
            opts += _opt(code, val)

        opts += bytes([OPT_END])
        return hdr + opts


def _opt(code, data):
    return bytes([code, len(data)]) + data


def _parse_opts(data):
    opts = {}
    i = 0
    while i < len(data):
        code = data[i]
        if code == OPT_END:
            break
        if code == 0:  # pad
            i += 1
            continue
        if i + 1 >= len(data):
            break
        length = data[i + 1]
        if i + 2 + length > len(data):
            break
        opts[code] = data[i + 2:i + 2 + length]
        i += 2 + length
    return opts
