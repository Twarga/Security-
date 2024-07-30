# Section 1 : Installing Nmap



# Section 2 : Basic Scanning Techniques
## Scan Single Target
To Scan a single Target we use the keyword nmap+ the hos or ip address of the target

```bash
nmap <ip-address or hostnam>
```

Example :
```bash
nmap 192.168.1.1
```



### Nmap Port States :

- Open :
An open port is a port actively responds to an incoming connection

- closed :
A closed port is a port on a target that actively responds to a probe but does not have any service running on the port. Closed ports are commonly found on systems where no firewall is in place to filter incoming traffic.

- Filtered :
Filtered ports are ports that are typically protected by a firewall of some sort that prevents Nmap from determining whther or not the port is open or closed.

- unfiltered :
An unfiltered post is a port that Nmap can access but is unable to determine whether it is open or closed .

- Open|Filtered
An open|filtered port is a port which Nmap believes to be open or filtered but cannot determine which exact state the port is actually in.

- Closed|Filtered
A closed|filtered port is a port that Nmap believes to bo closed or filtered but cannot determine which respective state the port is actually in.

## Scan Multiple Targets
Nmap can be used to scan multiple hosts at the same time. With following Syntax :
```bash
nmap < target1 target2 target 3 >
```
Example :
```bash
nmap 192.168.1.1 192.168.1.2 192.168.1.3
```

Tip : If all the targets are on the same subnet you could use the shortband notation of nmap

```bash
nmap 192.168.10.1,2,3
```




## Scan a Range of IP Addresses
A range of IP addresses can be used for target specification as demonstrated in the example below.

Usage Syntax :
```bash
nmap <Range of IP addresses >
```


Example
```bash
nmap 192.168.10.1-100
```

- In this exam is instructed to scan the range of IP addresses from `192.168.10.1` through `192.168.10.100`
- You can also use ranges to scan multiple networks/subnets, For example typing `nmap 192.168.100.*` would scan the class C IP networks of 192.168.1.* through 192.168.100*.
## Scan an entire Subnet
Nmap can be used to scan an entire subnet using CIDR (Classless Inter-Domain Routing) notation.

Usage Syntax:
```bash
nmap <Network/CIDR>
```
Example :
```bash
nmap 192.168.10.1/24
```
The above example intructs Nmap to scan the entire 192.168.10.0 network using CIDR notation. CIDR notation consists of the network address and subnet mask (in binary bits) seprated by a slash.

## Scan a List of Targets

If you have a larger number of systems to scan , you can enter the IP address (or host names) in a text file and use that file as input for Nmap on the command Line.

```bash
cat list.txt
```

Use Syntax :

```bash
nmap -iL list.txt

```
## Scan Random Targets
The -IR parameter can be used to select random internet hosts to scan. Nmap will randomly generate the specified number of targets and attempt to scan them.

Use Syntax :

```bash
nmap -iR <number of targets>
```
Example :

```bash
nmap -iR 3
```
Executing nmap -iR 3 instructs Nmap to randomly generate 3 IP addresses to scan.
There aren’t many good reasons to ever do a random scan unless you are working
on a research project (or just really bored). Additionally, if you do a lot of aggressive
random scanning you could end up getting in trouble with your internet service
provider.



## Exclude Targets from a Scan
The --exclude option is used with Nmap to exclude hosts from a scan.

Usage syntax :
```bash
nmap
```
Example
```bash
nmap 192.168.10.0/24 --exclude 192.168.10.100
```
The --exclude option is useful if you want to exclude specific hosts when scanning a large number of addresses. In the example above host `192.168.10.100` is excluded from the range of targets being scanned.

- You can Exclude Targets Using a List
The --excludefile option is similar to the --exclude option and can be used to provide a list of targets to exclude from a network scan.

Usage Syntax :
```bash
nmap <targets> --excludefile <list.txt>
```
Example:
```bash
nmap 192.168.10.0/24 --excludefile list.txt
```
## Perform an Aggressive Scan
The `-A` parameter instructs  Nmap to perform an aggressive scan.

Usage syntax:
```bash
nmap -A <target>
```

Example :
```bash
nmap -A 10.10.1.51
```
The aggressive scan selects some of the most commonly used options within Nmap and is provided as a simple alternative to typing a long string of command line arguments. The -A parameter is a synonym for several advanced options (like -O -sC --traceroute) which can also be accessed individually and are covered later in this book.
## Scan an IPv6 Target
The -6 parameter is used to perform a scan of an IP version 6 target.

Usage Sytntax :
```bash
nmap -6 <target>
```
Example
```bash
nmap -6 fe80::29aa:9db9:4164:d80e
```
# Section 3 : Discovery Options
Before port scanning a target , Nmap will attempt to send ICMP echo requests to see if the host is "alive". This can save time when scanning multiple hosts as Nmap will not waste time attempting to probe hosts that are not online. Becuase ICMP requests are often blocked by firewalls, Nmap will also attempt to connect to port 80 and 443 since these common web server ports are often open (even if ICMP  is not.).

## Don't Ping ('-Pn')
- Use Case : When you know a target is up, but ICMP requests are blocked by a firewall or IDS, preventing a normal ping scan.
- Example: Scanning a web server that blocks ping requests.
```bash
nmap -Pn 192.168.1.10
```


## Perform a Ping Only Scan ('-sn')
- Use Case : To quickly determine which hosts are up without performing a port scan.
- Example : Checking which devices are online in a subnet.
```bash
nmap -sn 192.168.1.0/24
```

## TCP SYN Ping ('-PS')
- Use Case : When ICMP is blocked, but you suspect that certain TCP ports might be open (e.g, web servers on port 80 and 443).
Usage Sytax :
```bash
nmap -PS<port1,port1,etc> <target>
```
Example: Checking if web servers are up by probing common web ports.
```bash
nmap -PS80,443 192.168.1.10
```

## TCP ACK Ping ('-PA')
- Use Case : Similar to RCP SYN Ping, but using ACK packets which may be more likely to get through some firewalls
Usage Syntax :
```bash
nmap -PA<port1,port1,etc> <target>
```
Example : Testing firewall rules or checking if a target is up by sending ACK packets to common ports.

```bash
nmap -PA89,443 192.168.1.10
```

## UDP Ping ('-PU')
- Use Case : To determine if hosts are up by sending UDP packets to common services (e.g DNS on port 53).
Usage Syntax :
```bash
nmap -PU<port1,port2,etc> <target>
```
- Example : Cheking if a DNS server is up.
``` bash
nmap -PU53 192.168.1.10
```



## SCTP INIT Ping (`-PY`)
The `-PY` parameter instructs Nmap to perform an SCTP INIT ping.
- Use Case: To check for hosts supporting the SCTP protocol (used in some telecommunications systems).

Usage Syntax:
```bash
nmap -PY[port1,port1,etc] [target]
```
- Example: Discovering SCTP-enabled hosts in a network.
```bash
nmap -PY80,443 192.168.1.10

```


## ICMP Echo Ping (`-PE`)
- Use Case : Standard ping request to see if a host is up.
Usage Syntax :
```bash
nmap -PE <target>
```
Example : Basic reachability test for a host
```bash
nmap -PE 192.168.1.10
```

## ICMP Timestamp PING ('-PP')
- Use Case: When ICMP Echo requests are blocked, but Timestamp requests might get through.
- Example : Checking if a network device is up by sending a timestamp request.
```bash
nmap -PP 192.168.1.10
```
## ICMP Address Mask Ping ('-PM')
- Use Case: Less common, but useful to check if a device reponds to Address Mask requests.

- Example : Discovering network devices that repond to address mask requests.
```bash
nmap -PM 192.168.1.10
```

## IP Protocol Ping ('-PO')
- Use Case : To see if any IP protocol (other than TCP/UDP/ICMP) might be active on the targe.
- Example : Checking for unusual IP protocols.
```bash
nmap -PO 192.168.1.10
```
## ARP Ping ('-PR')
- Use Case : On a Local Network, to reliably determine which hosts are up by sendign ARP requests.
- Example : Scanning for active devices on the local LAN
```bash
nmap -PR 192.168.1.0/24
```



## Traceroute ('--traceroute')
- Use Case: To map the path packets take to reach the target , useful for network diagnostics.
- Example : Tracing the route to a remote host.
```bash
nmap --traceroute 192.168.1.10
```

## Force Reverse DNS Resolution ('-R')
- Use Case : To force Nmap to resolve hostnames for IP addresses, even if it slows down the scan.
- Example: Ensuring all scanned IPs have hostnames resolved
```bash
nmap -R 192.168.1.0/24
```

## Disable Reverse DNS Resolution ('-n')
- Use Case: When you don't need hostname resolution, which speeds up the scan

- Example: Scanning a subnet quickly without resolving hostnames.
```bash
nmap -n 192.168.1.0/24
```

## Alternative DNS Lookup ('--system-dns')
- Use Case : To use the system's DNS resolver rather than Nmap's built-in resolver.
- Example : Relying on the system's DNS configuration for lookups.
``` bash
nmap --system-dns 192.168.1.10
```

## Manually Specify DNS Server(S)(--dns-server)
- Use Case : To specify custom DNS servers for resolving hostnames.
- Example : Using Google's DNS servers for resolution.
```bash
nmap --dns-servers 8.8.8.8,8.8.4.4 192.168.1.10
```

## Create a Host List ('-sL')
- Use Case : To generate a list of target hosts without scanning them , useful for verifying the target list.
- Example : Listing hosts in a subnet.
```bash
nmap -sL 192.168.1.0/24
```
# Section 4 : Advance Scanning Options

