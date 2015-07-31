# UDP Protocol Scanner

Also see: https://labs.portcullis.co.uk/tools/udp-proto-scanner/

udp-proto-scanner.pl scans by sending UDP probes (from udp-proto-scanner.conf)
to a list of targets:

$ udp-proto-scanner.pl -f ips.txt
$ udp-proto-scanner.pl -p ntp -f ips.txt

The probe names (for -p) are defined in udp-proto-scanner.conf.  List probe 
names using the -l option:
$ udp-proto-scanner.pl -l

## What's it used for?

It's used in the host-discovery and service-discovery phases of a pentest.
It can be helpful if you need to discover hosts that only offer UDP services
and are otherwise well firewalled - e.g. if you want to find all the DNS
servers in a range of IP addresses.  Alternatively on a LAN, you might want
a quick way to find all the TFTP servers.

Not all UDP services can be discovered in this way (e.g. SNMPv1 won't respond
unless you know a valid community string).  However, many UDP services can be
discovered, e.g.:
* DNS
* TFTP
* NTP
* NBT
* SunRPC
* MS SQL
* DB2
* SNMPv3

## It's not a portscanner

It won't give you a list of open and closed ports for each host.  It's simply
looking for specific UDP services.

## Efficiency

It's most efficient to run udp-proto-scanner.pl against whole networks (e.g.
256 IPs or more).  If you run it against small numbers of hosts it will seem
quite slow because it waits for 1 second between each different type of probe.

## Credits

The UDP probes are mainly taken from amap, nmap and ike-scan.
Inspiration for the scanning code was drawn from ike-scan.
