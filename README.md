# Dataplane router implementation
The project aims to implement the dataplane of a router. Thus, it is realized
correctly and efficiently sending frames from one host to another that have no
direct connection between them (point to point). The router forwards the
packets to the most suitable route for them to reach their destination.
##### Contributor: Dumitrascu Filip-Teodor

## Content
0. [Router's structures](#routers-structures)
1. [Forward process](#forward-process)
2. [LPM effective](#lpm-effective)
3. [ARP protocol](#arp-protocol)
4. [ICMP protocol](#icmp-protocol)

## Router's structures
Router cache and routing tables are allocated. In the routing table are the ip
prefixes, the mask with which the desired prefix is found, the next hop if
that route is chosen and the interface the packet should take. The cache
table is initially empty. It fills up as needed for the destination mac
address for the next ip hop. 

## Forward process
For a frame to get from one host to another via routers, the Internet Protocol
version 4 is used, and between entities (host/router), the MAC addresses of the
Ethernet Protocol are used. Their headers contain fields that are modified and
checked to ensure packet integrity and correct packet forwording. Thus, the
following steps are followed:

- Check if ip destination is the router itself
- Verify if checksum is the same after last send
- Decrease the time to live for a packet
- Search the longest prefix match to send the packet
- Recalculate the checksum
- Set the mac source and destination addresses
- Send the packet

## LPM effective
As routing tables are very large, searching through them can take a long time.
Thus, a trie is used where each node represents one bit of the prefix and only
the bits remaining after the destination ip prefix are inserted. (i.e. those
that have a corresponding bit equal to 1 in the mask).  When searching,
the trie iteration according to the destination ip is immediate. If the node it
reached is the end of a prefix, a route has been found. Otherwise, an icmp
message is sent.

## ARP protocol
When choosing a route on which to send the packet, the destination MAC address
of the next hop ip isn't known. Thus, the packet is hold in a queue and sent an
arp_request asking for the mac address. The router receives an arp_reply with
the mac address and sends all packets hold in the queue for which the destination
mac address is now known. Also, the mac address is stored in a cache table to not
send arp requests that have already been sent to those ip next hops.

## ICMP protocol
A control protocol that alerts the sender of the packet of any errors that may
have occurred during sending or answer the echo requests sent to the router.
So the 3 cases are treated:
- TTL exceeded
- Destination unreachable
- Router is destination
