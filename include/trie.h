// 323CA Dumitrascu Filip-Teodor
#ifndef TRIE_H
#define TRIE_H

#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>

/**
 * @struct Trie node type.
 * 
 * @param rte         used to memorize the route entry. If is not null,
 *                    the node is the end of an ip.
 * @param children    if is not null, children[bit] is the next bit.
 *
 */
typedef struct trie_node {
    struct route_table_entry *rte;
    struct trie_node **children;

} trie_node;

/**
 * @struct The type (trie) where the prefixes in the route table are stored.
 * 
 * @param root first node
 * @param size the number of nodes
 */
typedef struct trie_t {
    trie_node *root;
    int size;

} trie_t;

/**
 * @brief Creates a node according to the next bit. 
 */
trie_node *trie_create_node(void);

/**
 * @brief Create trie to memorize the routing table and iterate efficiently
 */
trie_t *trie_create(void);

/**
 * @brief Insert a route entry in the trie.
 * 
 * @param trie the trie
 * @param rte the route entry 
 */
void trie_insert(trie_t *trie, struct route_table_entry *rte);

/**
 * @brief Search in the trie the longest preffix match for a given ip address.
 * 
 * @param trie the trie
 * @param ip_dest the destination ip
 * 
 * @return the best route to reach the destination
 */
struct route_table_entry *lpm(trie_t *trie, uint32_t ip_dest);

#endif