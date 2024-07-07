// 323CA Dumitrascu Filip-Teodor
#include "lib.h"
#include "trie.h"

trie_node *trie_create_node(void)
{
    trie_node *node = malloc(sizeof(trie_node));
    DIE(!node, "malloc node\n");

    node->rte = NULL;

    node->children = calloc(MAX_CHILDREN, sizeof(trie_node *));
    DIE(!node->children, "calloc children\n");

    return node;
}

trie_t *trie_create(void)
{
    trie_t *trie = malloc(sizeof(trie_t));
    DIE(!trie, "malloc trie");

    trie->root = trie_create_node();

    trie->size = 1;
    
    return trie;
}

void trie_insert(trie_t *trie, struct route_table_entry *rte)
{
    uint32_t mask = ntohl(rte->mask);
    uint32_t prefix = ntohl(rte->prefix);

    /**
     * Count only the bits of 1 in the mask as they
     * form the prefix of the ip address when searching.
     */
    while ((mask & 1) == 0) { 
        mask >>= 1;
    }

    trie_node *current = trie->root;
    int which_bit = NUM_BITS_IPV4 - 1;

    /**
     * Knowing in the mask there are only 1s left,
     * insert in the trie from the prefix only the number of
     * bits in the mask left times.
     */
    while (mask) {
        /**
         * Shifts right as many times as necessary for each bit to reach
         * the last one, also ANDs with 1 to determine what value the bit has.
         */ 
        int bit = (prefix >> which_bit) & 1;

        if (!current->children[bit]) {
            current->children[bit] = trie_create_node();
            trie->size++;
        }

        current = current->children[bit];

        which_bit--;
        mask >>= 1;
    }

    current->rte = rte;
}

struct route_table_entry *lpm(trie_t *trie, uint32_t ip_dest)
{
    uint32_t ip = ntohl(ip_dest);
    struct route_table_entry* best_route = NULL;

    trie_node *current = trie->root;
    int which_bit = NUM_BITS_IPV4 - 1;

    /**
     * Iterates through the trie as much as possible following the ip_dest
     * and at the end returns the longest match found along the way.
     */
    while (current) {
        int bit = (ip >> which_bit) & 1;
        
        if (current->rte) {
            best_route = current->rte;
        }
        
        current = current->children[bit];
        which_bit--;
    }

    return best_route;
}
