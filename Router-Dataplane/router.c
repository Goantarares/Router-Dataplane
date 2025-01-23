#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <string.h>
#include <arpa/inet.h>
#include <stdio.h>
#define ETHERTYPE_IP 0x0800
#define ETHERTYOPE_ARP 0x0806

void print_ip_address(uint32_t ip_address) {
    printf("%u.%u.%u.%u\n", (ip_address >> 24) & 0xFF, (ip_address >> 16) & 0xFF, (ip_address >> 8) & 0xFF, ip_address & 0xFF);
}

struct trie_node {
    struct trie_node *children[2];
    struct route_table_entry *entry;
};

int count_bits_set(uint32_t num) {
    int count = 0;
    while (num) {
        count += num & 1;
        num >>= 1;
    }
    return count;
}

/* Routing table */
struct route_table_entry *rtable;
int rtable_len;

/* Mac table */
struct arp_table_entry *arp_table;
int arp_table_len;


struct trie_node* create_node() {
    struct trie_node *node = (struct trie_node*)malloc(sizeof(struct trie_node));
    if (node) {
        node->entry = NULL;
        for (int i = 0; i < 2; i++) {
            node->children[i] = NULL;
        }
    }
    return node;
}

struct route_table_entry *get_best_route(struct trie_node *root, uint32_t ip) {
	struct trie_node *curr = root;
    struct route_table_entry *best_route = NULL;

	ip = htonl(ip);

    // Parcurgem trie-ul
    for (int i = 31; i >= 0 && curr; i--) {

	// Dacă găsim o intrare la acest nivel, o salvăm ca rezultat
        if (curr->entry) {
            best_route = curr->entry;
        }

        int bit = (ip >> i) & 1; // Obținem bit-ul i din adresa IP

        // Verificăm dacă nodul pentru bit este null
        if (curr->children[bit] == NULL) {
            break; // Nu există nicio intrare corespunzătoare
        }

        // Trecem la următorul nod
        curr = curr->children[bit];
    }

    return best_route;
}


void insert(struct trie_node *root, struct route_table_entry *entry) {
	struct trie_node *curr = root;
    uint32_t mask = entry->mask;
    uint32_t prefix = htonl(entry->prefix);

    int relevant_bits = count_bits_set(mask);

    // Parcurgem trie-ul
    for (int i = 31; i >= 32 - relevant_bits; i--) {
        int bit = (prefix >> i) & 1; // Obținem bit-ul i din prefix

        // Verificăm dacă nodul pentru bit este null și îl creăm dacă este necesar
        if (curr->children[bit] == NULL) {
            curr->children[bit] = create_node();
        }

        // Trecem la următorul nod
        curr = curr->children[bit];
    }

    // Salvăm intrarea în nodul final
    curr->entry = entry;
}

struct trie_node* root = NULL;

struct arp_table_entry *get_arp_table_entry(uint32_t given_ip) {
	/* TODO 2.4: Iterate through the MAC table and search for an entry
	 * that matches given_ip. */

	/* We can iterate thrpigh the arp_table for (int i = 0; i <
	 * arp_table_len; i++) */
	for (int i = 0; i < arp_table_len; i++) {
		if (given_ip == arp_table[i].ip)
			return &arp_table[i];
	}
	return NULL;
}


int main(int argc, char *argv[])
{

	queue coada = queue_create();

	root = create_node();

	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	/* Code to allocate the MAC and route tables */
	rtable = malloc(sizeof(struct route_table_entry) * 80000);
	/* DIE is a arpro for sanity checks */
	DIE(rtable == NULL, "memory");

	arp_table = malloc(sizeof(struct  arp_table_entry) * 100);
	DIE(arp_table == NULL, "memory");

	/* Read the static routing table and the MAC table */
	printf("Reading routing table from file: %s\n", argv[1]);
	rtable_len = read_rtable(argv[1], rtable);

	for (int i = 0 ; i < rtable_len ; i++){

		insert(root, &rtable[i]);

	}



	printf("Routing table read successfully. Number of entries: %d\n", rtable_len);


	printf("Parsing ARP table from file: arp_table.txt\n");
	// arp_table_len = parse_arp_table("arp_table.txt", arp_table);

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */


		/* Check if we got an IPv4 packet */
		if (eth_hdr->ether_type == ntohs(ETHERTYPE_IP)) {

			printf("RECEIVED IP BEFORE PACKET");

			struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

			/* TODO 2.1: Check the ip_hdr integrity using ip_checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)) */
			printf("Checking IP header integrity...\n");
			uint16_t old_check = ip_hdr->check;
			ip_hdr->check = 0;
			uint16_t new_checksum = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));
			if (new_checksum != old_check) {
				printf("Error: IP header integrity check failed!\n");
				continue;
			}
			printf("IP header integrity checked successfully.\n");

			in_addr_t addr = inet_addr(get_interface_ip(interface)); // imi da ip-ul meu pe o anumita interfata

			if(ip_hdr->daddr == addr) { // if for me => e icmp, send icmp
				struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
				icmp_hdr->type = 0;
				icmp_hdr->checksum = 0;
				icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr)));
				
				printf("Am intrat in icmp");
				
				printf("ip-daddr %d\n", ip_hdr->daddr);
				uint32_t aux_ip_dest = ip_hdr->saddr;
				ip_hdr->saddr = ip_hdr->daddr;
				ip_hdr->daddr = aux_ip_dest;
				printf("ip-daddr %d\n", ip_hdr->daddr);

				uint8_t aux_ether_dest[6];
				memcpy(aux_ether_dest, eth_hdr->ether_shost, 6);
				memcpy(eth_hdr->ether_shost, eth_hdr->ether_dhost, 6);
				memcpy(eth_hdr->ether_dhost, aux_ether_dest, 6);

				send_to_link(interface, buf, len);
				continue;
			}


			/* TODO 2.2: Call get_best_route to find the most specific route, continue; (drop) if null */
			printf("Finding best route for destination IP: %u\n", ip_hdr->daddr);
			struct route_table_entry *best_route = get_best_route(root, ip_hdr->daddr);
			if (best_route == NULL) {
				
				size_t length = sizeof(struct ether_header) + 2*sizeof(struct iphdr) + sizeof(struct icmphdr) + 8;

				char *buffer = malloc(length);
				
				struct ether_header *eth_header = (struct ether_header *) buffer;
				struct iphdr *ip_header = (struct iphdr *)(buffer + sizeof(struct ether_header));
				struct icmphdr *icmp_header = (struct icmphdr *)(buffer + sizeof(struct ether_header) + sizeof(struct iphdr));
				struct iphdr *ip_header_dropped = (struct iphdr *)(buffer + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr));

				memcpy(eth_header->ether_dhost, eth_hdr->ether_shost, 6);
				memcpy(eth_header->ether_shost, eth_hdr->ether_dhost, 6);
				eth_header->ether_type = htons(ETHERTYPE_IP);
				printf("0x%x\n", eth_header->ether_type);
				
				ip_header->ihl = 5;
				ip_header->version = 4;   // we use version = 4
				ip_header->tos = 0;      // we don't use this, set to 0
				ip_header->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr) + 8);  // total length = ipheader + data
				ip_header->id = 1234;       // id of this packet
				ip_header->frag_off = 0; // we don't use fragmentation, set to 0
				ip_header->ttl = 64;      // Time to Live -> to avoid loops, we will decrement
				ip_header->protocol = 1; // don't care
				ip_header->saddr = addr;    // source address
				ip_header->daddr = ip_hdr->saddr;
				ip_header->check = 0; 
				ip_header->check = htons(checksum((uint16_t *)ip_header, sizeof(struct iphdr)));
				
				icmp_header->type = 3;
				icmp_header->code = 0;
				icmp_header->checksum = htons(checksum((uint16_t *)icmp_header, sizeof(struct icmphdr)) + sizeof(struct iphdr) + 8);
				
				ip_header_dropped->ihl = ip_hdr->ihl;
				ip_header_dropped->version = ip_hdr->version;   // we use version = 4
				ip_header_dropped->tos = ip_hdr->tos;      // we don't use this, set to 0
				ip_header_dropped->tot_len = ip_hdr->tot_len;  // total length = ipheader + data
				ip_header_dropped->id = ip_hdr->id;       // id of this packet
				ip_header_dropped->frag_off = ip_hdr->frag_off; // we don't use fragmentation, set to 0
				ip_header_dropped->ttl = ip_hdr->ttl;      // Time to Live -> to avoid loops, we will decrement
				ip_header_dropped->protocol = ip_hdr->protocol; // don't care
				ip_header_dropped->saddr = ip_hdr->saddr;    // source address
				ip_header_dropped->daddr = ip_hdr->daddr; 
				ip_header_dropped->check = ip_hdr->check;
				memcpy(ip_header_dropped + sizeof(struct iphdr), ip_hdr + sizeof(struct iphdr), 8);

				send_to_link(interface, buffer, length);
				free(buffer);

				continue;
			}
			printf("Best route found. Next hop: %u, Interface: %d\n", best_route->next_hop, best_route->interface);



			/* TODO 2.3: Check TTL >= 1. Update TLL. Update checksum  */
			if (ip_hdr->ttl <= 1) {

				size_t length = sizeof(struct ether_header) + 2*sizeof(struct iphdr) + sizeof(struct icmphdr) + 8;

				char *buffer = malloc(length);
				
				struct ether_header *eth_header = (struct ether_header *) buffer;
				struct iphdr *ip_header = (struct iphdr *)(buffer + sizeof(struct ether_header));
				struct icmphdr *icmp_header = (struct icmphdr *)(buffer + sizeof(struct ether_header) + sizeof(struct iphdr));
				struct iphdr *ip_header_dropped = (struct iphdr *)(buffer + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr));

				memcpy(eth_header->ether_dhost, eth_hdr->ether_shost, 6);
				memcpy(eth_header->ether_shost, eth_hdr->ether_dhost, 6);
				eth_header->ether_type = htons(ETHERTYPE_IP);
				printf("0x%x\n", eth_header->ether_type);
				
				ip_header->ihl = 5;
				ip_header->version = 4;   // we use version = 4
				ip_header->tos = 0;      // we don't use this, set to 0
				ip_header->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr) + 8);  // total length = ipheader + data
				ip_header->id = 1234;       // id of this packet
				ip_header->frag_off = 0; // we don't use fragmentation, set to 0
				ip_header->ttl = 64;      // Time to Live -> to avoid loops, we will decrement
				ip_header->protocol = 1; // don't care
				ip_header->saddr = addr;    // source address
				ip_header->daddr = ip_hdr->saddr;
				ip_header->check = 0; 
				ip_header->check = htons(checksum((uint16_t *)ip_header, sizeof(struct iphdr)));
				
				icmp_header->type = 11;
				icmp_header->code = 0;
				icmp_header->checksum = htons(checksum((uint16_t *)icmp_header, sizeof(struct icmphdr)) + sizeof(struct iphdr) + 8);
				
				ip_header_dropped->ihl = ip_hdr->ihl;
				ip_header_dropped->version = ip_hdr->version;   // we use version = 4
				ip_header_dropped->tos = ip_hdr->tos;      // we don't use this, set to 0
				ip_header_dropped->tot_len = ip_hdr->tot_len;  // total length = ipheader + data
				ip_header_dropped->id = ip_hdr->id;       // id of this packet
				ip_header_dropped->frag_off = ip_hdr->frag_off; // we don't use fragmentation, set to 0
				ip_header_dropped->ttl = ip_hdr->ttl;      // Time to Live -> to avoid loops, we will decrement
				ip_header_dropped->protocol = ip_hdr->protocol; // don't care
				ip_header_dropped->saddr = ip_hdr->saddr;    // source address
				ip_header_dropped->daddr = ip_hdr->daddr; 
				ip_header_dropped->check = ip_hdr->check;
				memcpy(ip_header_dropped + sizeof(struct iphdr), ip_hdr + sizeof(struct iphdr), 8);

				send_to_link(interface, buffer, length);
				free(buffer);

				continue;
			}

			printf("Updating TTL...\n");
			ip_hdr->ttl--;
			ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

			/* TODO 2.4: Update the ethernet addresses. Use get_arp_table_entry to find the destination MAC
			* address. Use get_interface_arp(m.interface, uint8_t *arp) to
			* find the arp address of our interface. */
			printf("Updating Ethernet addresses...\n");
			struct arp_table_entry *mcDonalds = get_arp_table_entry(best_route->next_hop);
			if (mcDonalds == NULL) {
				printf("ARP entry not found for next hop IP: %u\n", best_route->next_hop);
				char *new_buff = malloc(MAX_PACKET_LEN);
				memcpy(new_buff, buf, MAX_PACKET_LEN);
				queue_enq(coada, new_buff);
				struct arp_header *new_hdr = (struct arp_header *)ip_hdr;

				new_hdr->htype = htons(1);   /* Format of hardware address */
				new_hdr->ptype = htons(ETHERTYPE_IP);   /* Format of protocol address */
				new_hdr->hlen = 6;    /* Length of hardware address */
				new_hdr->plen = 4;    /* Length of protocol address */
				new_hdr->op = htons(1);    /* ARP opcode (command) */
				uint8_t mac[6];
				get_interface_mac(best_route->interface, mac);
				memcpy(new_hdr->sha, mac, 6);  /* Sender hardware address */ //get mac interface si memcpy
				new_hdr->spa = addr;   /* Sender IP address */
				//tha idk
				new_hdr->tpa = best_route->next_hop;

				eth_hdr->ether_type = htons(ETHERTYOPE_ARP);

				memcpy(eth_hdr->ether_shost, &mac, 6);
				mac[0] = 0xff;
				mac[1] = 0xff;
				mac[2] = 0xff;
				mac[3] = 0xff;
				mac[4] = 0xff;
				mac[5] = 0xff;

				memcpy(eth_hdr->ether_dhost, &mac, 6);

				send_to_link(best_route->interface, buf, sizeof(struct ether_header) + sizeof(struct arp_header));

				continue;
			}

			uint8_t mac[6];
			get_interface_mac(best_route->interface, mac);

			memcpy(eth_hdr->ether_dhost, mcDonalds->mac, 6);
			memcpy(eth_hdr->ether_shost, &mac, 6);

			printf("Sending packet on interface %d...\n", best_route->interface);
			send_to_link(best_route->interface, buf, len);
		} else {
			printf("RECEIVED ARP\n");

			struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));


			if (arp_hdr->op == ntohs(1)) {
				printf("ARP WITH OP REQUEST\n");

				in_addr_t addr = inet_addr(get_interface_ip(interface));

				uint8_t mac[6];
				get_interface_mac(interface, mac);

				// pun macul destinatie ca macul de unde a venit
				memcpy(eth_hdr->ether_dhost, arp_hdr->sha, 6);
				memcpy(eth_hdr->ether_shost, mac, 6);

				memcpy(arp_hdr->tha, arp_hdr->sha, 6);
				memcpy(arp_hdr->sha, mac, 6);

				arp_hdr->tpa = arp_hdr->spa;
				arp_hdr->spa = addr;

				// setez ca reply si trimit de unde a venit
				arp_hdr->op = htons(2);

				send_to_link(interface, buf, len);
				continue;
			}
			else if (arp_hdr->op == ntohs(2))
			{
				printf("RECEIVED ARP REPLY\n");
				arp_table[arp_table_len].ip = arp_hdr->spa;
				memcpy(arp_table[arp_table_len].mac, arp_hdr->sha, 6);
				arp_table_len += 1;
				queue aux_queue = queue_create();

				while(queue_empty(coada) != 1) {

					char *buff = queue_deq(coada);
					struct ether_header *aux_ether_hdr = (struct ether_header *)(buff); 
					struct iphdr *aux_ip_hdr = (struct iphdr *)(buff + sizeof(struct ether_header));
					int aux_len = htons(aux_ip_hdr->tot_len) + sizeof(struct ether_header);

					printf("god bless\n");
					struct route_table_entry *bis = get_best_route(root, aux_ip_hdr->daddr);
					printf("0x%p\n", bis);

					struct arp_table_entry *arp_entry = get_arp_table_entry(bis->next_hop);
					if(!arp_entry) {
						queue_enq(aux_queue, buff);
						continue;
					} else {
						printf("first\n");
						get_interface_mac(bis->interface, aux_ether_hdr->ether_shost);
						memcpy(aux_ether_hdr->ether_dhost, arp_entry->mac, 6);
						printf("1\n");
						send_to_link(bis->interface, buff, aux_len);
					}
				}
				coada = aux_queue;
			}
		}
	}
}