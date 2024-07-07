// 323CA Dumitrascu Filip-Teodor
#ifndef _SKEL_H_
#define _SKEL_H_

#include "trie.h"
#include "queue.h"

#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define MAX_PACKET_LEN 1600
#define ROUTER_NUM_INTERFACES 3

// trie macros
#define MAX_CHILDREN 2
#define NUM_BITS_IPV4 (IP_LEN * 8)

// cache table macro
#define MAX_HOSTS 100

// ethernet macros
#define MAC_LEN 6
#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806

// ip macros
#define IP_LEN 4
#define IP_VERSION 4
#define IP_NO_OPTIONS 5
#define IP_MAX_TTL 64

// arp macros
#define ARP_REQ 1
#define ARP_REP 2
#define ARP_HW_ETH 1

// icmp macros
#define ICMP_PROT 1
#define ICMP_NO_FRAGMENT 1
#define ICMP_DEST_UNR_TYPE 3
#define ICMP_DEST_UNR_CODE 0
#define ICMP_TIME_EXC_TYPE 11
#define ICMP_TIME_EXC_CODE 0
#define ICMP_ECHOREPLY_TYPE 0 
#define ICMP_ECHOREPLY_CODE 0

/*
 * @brief Sends a packet on a specific interface.
 *
 * @param interface - index of the output interface
 * @param frame_data - region of memory in which the data will be copied; should
 *        have at least MAX_PACKET_LEN bytes allocated
 * @param length - will be set to the total number of bytes received.
 * Returns: the interface it has been received from.
 */
int send_to_link(int interface, char *frame_data, size_t length);

/*
 * @brief Receives a packet. Blocking function, blocks if there is no packet to
 * be received.
 *
 * @param frame_data - region of memory in which the data will be copied; should
 *        have at least MAX_PACKET_LEN bytes allocated 
 * @param length - will be set to the total number of bytes received.
 * Returns: the interface it has been received from.
 */
int recv_from_any_link(char *frame_data, size_t *length);

/**
 * @struct Route table entry type.
 * 
 * @param next_hop       the ip address where the packet would be sent
 * @param mask           the mask used in AND operation to check if
 * 					     the ip address has this @param prefix
 * @param send_interface the interface from which the packet would be sent 
 */
struct route_table_entry {
	uint32_t prefix;
	uint32_t next_hop;
	uint32_t mask;
	int send_interface;
} __attribute__((packed));

/**
 * @struct  Arp table entry type.
 * 
 * @param ip    the ip
 * @param mac   the mac address
 */
typedef struct arp_table_entry {
    uint32_t ip;
    uint8_t mac[6];
} arp_table_entry;

/**
 * @struct Arp table type.
 * 
 * @param q             the queue used to hold the packet untill
 * 			            the router knows it's mac dest
 * @param len           the size of the arp table
 * @param arp_entries   the entries in the table
 */
typedef struct arp_table {
	queue q;
	size_t len;
	arp_table_entry **arp_entries;
} arp_table;

/**
 * @struct Type used for holding the information of a packet in a queue.
 * 
 * @param buf            the buffer
 * @param len            the size of the buffer
 * @param next_hop       the ip address where the packet would be sent
 * @param send_interface the interface from which the packet would be sent 
 */
typedef struct package_on_hold {
	char *buf; 
    size_t len;
	uint32_t next_hop;
	int send_interface;
} package_on_hold;

char *get_interface_ip(int interface);

/**
 * @brief Get the interface mac object. The function writes
 * the MAC at the pointer mac. uint8_t *mac should be allocated.
 *
 * @param interface
 * @param mac
 */
void get_interface_mac(int interface, uint8_t *mac);

/**
 * @brief Homework infrastructure function.
 *
 * @param argc
 * @param argv
 */

/**
 * @brief IPv4 checksum per  RFC 791. To compute the checksum
 * of an IP header we must set the checksum to 0 beforehand.
 *
 * also works as ICMP checksum per RFC 792. To compute the checksum
 * of an ICMP header we must set the checksum to 0 beforehand.

 * @param data memory area to checksum
 * @param length in bytes
 */
uint16_t checksum(uint16_t *data, size_t length);

/**
 * hwaddr_aton - Convert ASCII string to MAC address (colon-delimited format)
 * @txt: MAC address as a string (e.g., "00:11:22:33:44:55")
 * @addr: Buffer for the MAC address (ETH_ALEN = 6 bytes)
 * Returns: 0 on success, -1 on failure (e.g., string not a MAC address)
 */
int hwaddr_aton(const char *txt, uint8_t *addr);

/* Populates a route table from file, rtable should be allocated
 * e.g. rtable = malloc(sizeof(struct route_table_entry) * 80000);
 * This function returns the size of the route table.
 */
int read_rtable(const char *path, trie_t *rtable);

/* Parses a static mac table from path and populates arp_table.
 * arp_table should be allocated and have enough space. This
 * function returns the size of the arp table.
 * */
int parse_arp_table(char *path, struct arp_table_entry *arp_table);

void init(int argc, char *argv[]);

#define DIE(condition, message, ...) \
	do { \
		if ((condition)) { \
			fprintf(stderr, "[(%s:%d)]: " # message "\n", __FILE__, __LINE__, ##__VA_ARGS__); \
			perror(""); \
			exit(1); \
		} \
	} while (0)

#endif /* _SKEL_H_ */
