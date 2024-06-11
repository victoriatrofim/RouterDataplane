#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "lib.h"
#include "protocols.h"
#define MAX 100000

/* Routing table */
struct route_table_entry *rtable;
int rtable_len;

/* ARP table */
struct arp_table_entry *arp_table;
int arp_table_len;

/* Address Lookup using Trie */
struct trie {
	struct route_table_entry *route;
	struct trie *zero;
	struct trie *one;
};

/* Head of Trie */
struct trie *head;

/* Add a node to the Trie */
void add_trie_node(struct route_table_entry *route)
{
	uint32_t mask;
	int pos;
	struct trie *node;

	// Verify if trie exists
	if (head == NULL) {
		head = malloc(sizeof(struct trie));
		DIE(head == NULL, "malloc fail");
		head->route = NULL;
		head->zero = NULL;
		head->one = NULL;
	}
	// current mask
	mask = 0;
	// current position of byte
	pos = 31;
	// current node
	node = head;
	while(1) {
		uint8_t byte;

		if (mask == ntohl(route->mask)) {
			// Set the route for the node
			node->route = route; 
			break;
		}

		// Find the bit at position pos + traverse down one level in Trie
		byte = (ntohl(route->prefix) & (1 << pos)) >> pos;
		if (byte == 0) {
			if (node->zero == NULL) {
				node->zero = malloc(sizeof(struct trie));
				DIE(node->zero == NULL, "memory"); 
				node->zero->route = NULL;
				node->zero->zero = NULL;
				node->zero->one = NULL;
			}
			node = node->zero;
		}
		else {
			if (node->one == NULL) {
				node->one = malloc(sizeof(struct trie));
				DIE(node->one == NULL, "memory"); 
				node->one->route = NULL;
				node->one->zero = NULL;
				node->one->one = NULL;
			}
			node = node->one;
		}
		// Update the mask
		mask = (mask >> 1) | (1 << 31); 
		pos --;
	}
}

void ICMP_REPLY(int interface, char *buf) 
{
    struct ether_header *eth_hdr;
    struct iphdr *ip_hdr;
    struct icmphdr *icmp_hdr;
    
    // Extract the Ethernet, IP and ICMP headers
    eth_hdr = (struct ether_header *) buf;
    ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
    icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));

    // Swap source and destination in Ethernet Header
    uint8_t temp_eth[6];
    memcpy(temp_eth, eth_hdr->ether_shost, 6);
    memcpy(eth_hdr->ether_shost, eth_hdr->ether_dhost, 6);
    memcpy(eth_hdr->ether_dhost, temp_eth, 6);

    // Swap source and destination in IP Header 
    uint32_t temp_ip = ip_hdr->saddr;
    ip_hdr->saddr = ip_hdr->daddr;
    ip_hdr->daddr = temp_ip;

    // Decrement TTL and update checksum in IP Header
    uint16_t old_ttl = ip_hdr->ttl;
    ip_hdr->ttl--;
    ip_hdr->check += htons(old_ttl - ip_hdr->ttl);

    // Update ICMP Header to echo reply
    icmp_hdr->type = 0; // ICMP echo reply type is 0
    icmp_hdr->code = 0;
    icmp_hdr->checksum = 0;
    icmp_hdr->checksum = htons(checksum((uint16_t*)icmp_hdr, ntohs(ip_hdr->tot_len) - sizeof(struct iphdr)));

    // Send the packet
    send_to_link(interface, buf, 100);
}


//Create a Trie table
void create_trie_table()
{
	for(int i = 0; i < rtable_len; i++)
		add_trie_node(&rtable[i]);
}

struct route_table_entry *get_best_route(uint32_t ip_dest)
{
	struct route_table_entry *best_route;
	int pos;
	struct trie *node;

	best_route = NULL;
	pos = 31;
	node = head;
	while (pos >= 0 && node != NULL) {
		uint8_t byte;

		// Found a new route
		if (node->route != NULL)
			best_route = node->route;

		// Find the bit at position pos + traverse down one level in the Trie
		byte = (ntohl(ip_dest) & (1 << pos)) >> pos;
		if (byte == 0)
			node = node->zero;
		else
			node = node->one;

		pos --;
	}

	return best_route;
}

struct arp_table_entry *get_arp_table_entry(uint32_t given_ip) {
	for (size_t i = 0; i < arp_table_len; i++){
		if (arp_table[i].ip == given_ip) {
			// Return the ARP table entry if IP matches
			return &arp_table[i]; 
		}
	}
	return NULL; // if IP is not found in ARP table
}

int main(int argc, char *argv[])
{
	// Buffer to store received packet
	char buf[MAX]; 

	init(argc - 2, argv + 2); 

	/* Code to allocate the MAC and route tables */
	rtable = malloc(MAX * sizeof(struct route_table_entry)); 
	DIE(rtable == NULL, "error"); 

	arp_table = malloc(MAX * sizeof(struct arp_table_entry));
	DIE(arp_table == NULL, "error"); 

	/* Read the static routing table and the ARP table */
	rtable_len = read_rtable(argv[1], rtable); 
	arp_table_len = parse_arp_table("arp_table.txt", arp_table); 
	// Create Trie table for routing
	create_trie_table(); 

	while (1) {
		int interface;
		size_t len;
		uint32_t interface_ip;
		uint8_t interface_mac[6];
		
		// Receive packet from any interface
		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "get_message");
		interface_ip = inet_addr(get_interface_ip(interface));
		get_interface_mac(interface, interface_mac);

		// Extract Ethernet header from packet
		struct ether_header *eth_hdr = (struct ether_header *) buf;
		// Extract IP header from packet, skipping eth header
		struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

		// Check if packet is IPv4
		if (eth_hdr->ether_type != ntohs(0x0800)) {
			continue;
		}
		/* Check if it is the destination */
			if (interface_ip == ip_hdr->daddr) {
			ICMP_REPLY(interface, buf);			
			continue;
			}

		uint32_t check = ntohs(ip_hdr->check);
		ip_hdr->check = 0;

		// Check IP header checksum
		if (check == checksum((uint16_t *)ip_hdr, sizeof(struct iphdr))) {
			// Get the best route for destination IP
			if (get_best_route(ip_hdr->daddr) != NULL) {
				struct route_table_entry best_router = *(get_best_route(ip_hdr->daddr));

				// Check TTL
				if (ip_hdr->ttl >= 1) {
					ip_hdr->ttl--;
					// Recalculate checksum
					uint16_t new_checksum = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));
					// Set new checksum
					ip_hdr->check = htons(new_checksum);

					// Check ARP table for next hop
					if (get_arp_table_entry(best_router.next_hop) != NULL) {
						uint8_t new_dest_mac[6];
						// Get MAC address of next hop
						memcpy(new_dest_mac, (*(get_arp_table_entry(best_router.next_hop))).mac, 6);
						// Set destination MAC address in Ethernet header
						memcpy(eth_hdr->ether_dhost, new_dest_mac, 6);

						uint8_t new_source_mac[6];
						// Get MAC address of outgoing interface
						get_interface_mac(best_router.interface, new_source_mac);
						// Set source MAC address in Ethernet header
						memcpy(eth_hdr->ether_shost, new_source_mac, 6);

						// Send packet to outgoing interface
						send_to_link(best_router.interface, buf, len);
					}
					continue;
				}
				continue;
			}
			continue;
		}
		continue;
	}
}
