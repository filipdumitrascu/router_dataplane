// 323CA Dumitrascu Filip-Teodor
#include "lib.h"
#include "protocols.h"

#include <string.h>
#include <arpa/inet.h>

arp_table_entry *get_mac_entry(uint32_t given_ip, arp_table *atable)
{
	/**
	 * Iterate through a cache table, where all dest mac addresses discovered
	 * in previous arp requests were stored, and return the arp_entry if exits.
	 */
	for (int i = 0; i < atable->len; i++) {
		if (atable->arp_entries[i]->ip == given_ip) {
			return atable->arp_entries[i];
		}
	}

	return NULL;
}

package_on_hold *hold_packet(char *buf, size_t len,
 							 struct route_table_entry *best_route)
{
	/**
	 * Stores the packet information. 
	 */
	package_on_hold *packet = malloc(sizeof(package_on_hold));
	packet->buf = calloc(MAX_PACKET_LEN, sizeof(char));
	memcpy(packet->buf, buf, len);

	packet->len = len;
	packet->next_hop = best_route->next_hop;
	packet->send_interface = best_route->send_interface;

	return packet;
}

void send_arp(struct arp_header *arp_req, int interface,
			  int send_type, uint32_t next_hop)
{
	char buf[MAX_PACKET_LEN];
    size_t len = sizeof(ether_header) + sizeof(struct arp_header);

	/**
	 * Set the ethernet protocol in the packet. 
	 */
	ether_header *eth_hdr = (ether_header *) buf;
	get_interface_mac(interface, eth_hdr->ether_shost);
	eth_hdr->ether_type = htons(ETHERTYPE_ARP);


	/**
	 * Set the arp protocol encapsulated. 
	 */
	struct arp_header *arp_hdr = (struct arp_header *) (buf + sizeof(ether_header));
	arp_hdr->htype = htons(ARP_HW_ETH);
	arp_hdr->ptype = htons(ETHERTYPE_IP);
	arp_hdr->hlen = MAC_LEN;
	arp_hdr->plen = IP_LEN;
	arp_hdr->op = htons(send_type);

	get_interface_mac(interface, arp_hdr->sha);
	arp_hdr->spa = inet_addr(get_interface_ip(interface));

	/**
	 * Source mac, source ip, wanted ip and dest ip are set. 
	 */
	if (arp_req) {
		memcpy(eth_hdr->ether_dhost, arp_req->sha, MAC_LEN);
		memcpy(arp_hdr->tha, arp_req->sha, MAC_LEN);
		arp_hdr->tpa = arp_req->spa;
	
	} else {
		memset(eth_hdr->ether_dhost, 0xff, MAC_LEN);
		memset(arp_hdr->tha, 0x0, MAC_LEN);
		arp_hdr->tpa = next_hop;
	}

	int sent = send_to_link(interface, buf, len);
	DIE(sent < 0, "Failed to send arp\n");
}

void send_icmp(char *buf, size_t len, int interface, int type, int code)
{
	/**
	 * The packet for which an icmp response is needed. 
	 */
	ether_header *recv_eth = (ether_header *)buf;
	iphdr *recv_ip = (iphdr *) (buf + sizeof(ether_header));

	char msg[MAX_PACKET_LEN];
	memset(msg, 0, MAX_PACKET_LEN);
	size_t send_len;
	
	if (type == ICMP_ECHOREPLY_TYPE) {
		send_len = len;
	} else {
		send_len = len + sizeof(iphdr) + sizeof(icmphdr);
	}

	/**
	 * Set the ethernet protocol in the packet. 
	 */
	ether_header *send_eth = (ether_header*) msg;
	send_eth->ether_type = htons(ETHERTYPE_IP);
	memcpy(send_eth->ether_shost, recv_eth->ether_dhost, MAC_LEN);
	memcpy(send_eth->ether_dhost, recv_eth->ether_shost, MAC_LEN);

	/**
	 * Set the ip protocol encapsulated. 
	 */
	iphdr *send_ip = (iphdr*) (msg + sizeof(ether_header));
	send_ip->version = IP_VERSION;
	send_ip->ihl = IP_NO_OPTIONS;
	send_ip->tos = 0;
	send_ip->tot_len = htons(send_len - sizeof(ether_header));
	send_ip->id = htons(ICMP_NO_FRAGMENT);
	send_ip->frag_off = 0;
	send_ip->ttl = IP_MAX_TTL;
	send_ip->protocol = ICMP_PROT;
	send_ip->check = 0;
	send_ip->check = htons(checksum((uint16_t*) send_ip, sizeof(iphdr)));
	send_ip->saddr = inet_addr(get_interface_ip(interface));
	send_ip->daddr = recv_ip->saddr;


	/**
	 * Set the icmp protocol encapsulated. 
	 */
	icmphdr *snd_icmp = (icmphdr*) (msg + sizeof(ether_header) + sizeof(iphdr));
	size_t icmp_len = send_len - (sizeof(ether_header) + sizeof(iphdr));

	/**
	 *  If the icmp is an echo reply, copy icmp_len values from
	 * 	echo request(recv) to echo reply(send). Else, copy only the
	 * 	first 8 bytes for the error. 
	 */
	if (type == ICMP_ECHOREPLY_TYPE) {
		icmphdr *recv_icmp = (icmphdr*) (buf + sizeof(ether_header) + sizeof(iphdr));
		memcpy(snd_icmp, recv_icmp, icmp_len);

	} else {
		char *payload = ((char *) snd_icmp) + 8;
    	memcpy(payload, recv_ip, len - sizeof(ether_header));
	}

	snd_icmp->type = type;
	snd_icmp->code = code;
	snd_icmp->checksum = 0;
	snd_icmp->checksum = htons(checksum((uint16_t*) snd_icmp, icmp_len));


	int sent = send_to_link(interface, msg, send_len);
	DIE(sent < 0, "Failed to send icmp\n");
}

void forward_ip(char *buf, size_t len, int recv_interface,
				trie_t *rtable, arp_table *atable)
{
	iphdr *ip_hdr = (iphdr *) (buf + sizeof(ether_header));   

	/**
	 * If the ip destination is the router itself sends an Echo reply.
	 */
	if (ip_hdr->daddr == inet_addr(get_interface_ip(recv_interface))) {
		send_icmp(buf, len, recv_interface, ICMP_ECHOREPLY_TYPE, ICMP_ECHOREPLY_CODE);
		return;
    }

	/**
	 * Verifies if the checksum is the same after last send. 
	 */
	uint16_t check = ntohs(ip_hdr->check);
	ip_hdr->check = 0;
	if (checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)) != check) {
		printf("Frame corrupted\n"); 
		return;
	}

	/**
	 * Decreases the time to live and sends an error if it needs to be droped. 
	 */
	if (ip_hdr->ttl <= 1) {
		send_icmp(buf, len, recv_interface, ICMP_TIME_EXC_TYPE, ICMP_TIME_EXC_CODE);
		return;
	}
	ip_hdr->ttl--;

	/**
	 * Search the best route to send the packet.
	 * If there is no route, sends an error. 
	 */
	struct route_table_entry *best_route = lpm(rtable, ip_hdr->daddr);
	if (!best_route) {
		send_icmp(buf, len, recv_interface, ICMP_DEST_UNR_TYPE, ICMP_DEST_UNR_CODE);
		return;
	}

	/**
	 * Because the ttl was decremented, recalculate the
	 * checksum and assign it in the ip header. 
	 */
	ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

	/**
	 * Sets the mac source and destination addresses:
	 */
	arp_table_entry *entry = get_mac_entry(best_route->next_hop, atable);

	/**
	 * If the dest mac of the next hop isn't in the arp cache table,
	 * The packet is put on hold in a queue and an arp request is sent.
	 */
	if (!entry) {
		queue_enq(atable->q, hold_packet(buf, len, best_route));
		send_arp(NULL, best_route->send_interface, ARP_REQ, best_route->next_hop);
        return;
	}

	/**
	 * But if the dest mac is in the table, no need for an arp request
	 */
	ether_header *eth_hdr = (ether_header *) buf;
	memcpy(eth_hdr->ether_dhost, entry->mac, MAC_LEN);
	
	/**
	 * The source mac is the mac of the interface that was
	 * chosen to be used for the best route.
	 */
	get_interface_mac(best_route->send_interface, eth_hdr->ether_shost);

	/**
	 * Sends the packet. 
	 */
	int sent = send_to_link(best_route->send_interface, buf, len);
	DIE(sent < 0, "Failed to send\n");
}

void forward_arp(char *buf, int recv_interface, arp_table *atable)
{
	struct arp_header *arp_hdr = (struct arp_header*) (buf + sizeof(ether_header));

	/**
	 * If an arp request was received, an arp reply has to be sent. 
	 */
	if (ntohs(arp_hdr->op) == ARP_REQ) {
		send_arp(arp_hdr, recv_interface, ARP_REP, 0);
		return;
	}

	/**
	 * Else an arp reply was received and the
	 * dest mac is stored in the cache table.
	 */
	atable->arp_entries[atable->len] = malloc(sizeof(arp_table_entry));
	atable->arp_entries[atable->len]->ip = arp_hdr->spa;
	memcpy(atable->arp_entries[atable->len]->mac, arp_hdr->sha, MAC_LEN);
	atable->len++;

	queue aux = queue_create();
	
	/**
	 * Sends all packets whose destination mac
	 * was discovered from the last arp reply.
	 */
	while (!queue_empty(atable->q)) {
		package_on_hold *packet = (package_on_hold *) queue_deq(atable->q);
		arp_table_entry *entry = get_mac_entry(packet->next_hop, atable);

		if (!entry) {
			/**
			 * If the destination mac for the packet is not yet known,
			 * put it in an auxiliary queue to route the rest of the
			 * packets and then put it back in the main queue. 
			 */
			queue_enq(aux, packet);
			continue;
		}
		
		ether_header *pack_eth_hdr = (ether_header *) packet->buf;

		memcpy(pack_eth_hdr->ether_dhost, entry->mac, MAC_LEN);
		get_interface_mac(packet->send_interface, pack_eth_hdr->ether_shost);
		
		int sent = send_to_link(packet->send_interface, packet->buf, packet->len);
		DIE(sent < 0, "Failed to send after arp reply\n");
	}

	while (!queue_empty(aux)) {
		package_on_hold *packet = (package_on_hold *) queue_deq(aux);
		queue_enq(atable->q, packet);
	}

	free(aux);
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];
	init(argc - 2, argv + 2);

	/**
	 * The routing table. 
	 */
	trie_t *rtable = trie_create();
	read_rtable(argv[1], rtable);

	/**
	 * The cache table with mac addresses.
	 */
	arp_table *atable = malloc(sizeof(arp_table));
	atable->arp_entries = calloc(MAX_HOSTS, sizeof(arp_table_entry *));
	atable->len = 0;
	atable->q = queue_create();

	while (1) {
		size_t len;

		/**
		 * The router receives a packet. 
		 */
		int recv_interface = recv_from_any_link(buf, &len);
		DIE(recv_interface < 0, "recv_from_any_links");

		/**
		 * The package is parsed.
		 */
		if (len < sizeof(ether_header)) {
			printf("Frame too short\n");
			continue;
		}
		ether_header *eth_hdr = (ether_header *) buf;

		/**
		 * Check if the packet had to reach the 
		 * router itself or to anyone via broadcast.
		 */
		uint8_t recv[MAC_LEN], broadcast[MAC_LEN];
		get_interface_mac(recv_interface, recv);
		memset(broadcast, 0xff, MAC_LEN);
		
		if (memcmp(eth_hdr->ether_dhost, broadcast, MAC_LEN)
		 	&& memcmp(eth_hdr->ether_dhost, recv, MAC_LEN)) {
		 	printf("Wrong receiver\n");
		 	continue;
		}

		/**
		 * Treat encapsulated protocol.
		 */
		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
			forward_ip(buf, len, recv_interface, rtable, atable);
			continue;
		}

		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
			forward_arp(buf, recv_interface, atable);
			continue;
		}

		printf("Ignored non IPv4/ARP packet\n");
	}
}
