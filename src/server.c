#include <stdio.h>
#include <stdbool.h>
#include <malloc.h>
#define DONT_MAKE_WRAPPER
#include <_malloc.h>
#undef DONT_MAKE_WRAPPER
#include <util/event.h>
#include <util/map.h>
#include <util/list.h>
#include <net/ether.h>
#include <net/arp.h>
#include <net/ip.h>
#include <net/icmp.h>
#include <net/checksum.h>

#include "service.h"
#include "session.h"
#include "server.h"

#define ARP_TABLE	"net.arp.arptable"
#define ARP_TABLE_GC	"net.arp.arptable.gc"

#define GC_INTERVAL	(10 * 1000000)	// 10 secs

typedef struct {
	uint64_t	mac;
	uint64_t	timeout;
} ARPEntity;

bool server_arp_process(Packet* packet) {
	Ether* ether = (Ether*)(packet->buffer + packet->start);
	if(endian16(ether->type) != ETHER_TYPE_ARP)
		return false;
	
	Map* arp_table = ni_config_get(packet->ni, ARP_TABLE);
	if(!arp_table) {
		arp_table = map_create(32, map_uint64_hash, map_uint64_equals, packet->ni->pool);
		ni_config_put(packet->ni, ARP_TABLE, arp_table);
	}
	
	clock_t current = clock();
	
	// GC
	uint64_t gc_time = (uint64_t)ni_config_get(packet->ni, ARP_TABLE_GC);
	if(gc_time == 0 && !ni_config_contains(packet->ni, ARP_TABLE_GC)) {
		gc_time = current + GC_INTERVAL;
		ni_config_put(packet->ni, ARP_TABLE_GC, (void*)gc_time);
	}
	
	if(gc_time < current) {
		MapIterator iter;
		map_iterator_init(&iter, arp_table);
		while(map_iterator_has_next(&iter)) {
			MapEntry* entry = map_iterator_next(&iter);
			if(((ARPEntity*)entry->data)->timeout < current) {
				map_iterator_remove(&iter);
				__free(entry->data, packet->ni->pool);
			}
		}
		
		gc_time = current + GC_INTERVAL;
		ni_config_put(packet->ni, ARP_TABLE_GC, (void*)gc_time);
	}
	
	ARP* arp = (ARP*)ether->payload;
	switch(endian16(arp->operation)) {
		case 1:	// Request
			;
			List* private_interfaces = ni_config_get(packet->ni, "pn.lb.private_interfaces");
			if(list_is_empty(private_interfaces))
				return false;
			ListIterator iter;
			list_iterator_init(&iter, private_interfaces);
			while(list_iterator_has_next(&iter)) {
				Interface* private_interface = list_iterator_next(&iter);
				uint32_t addr = private_interface->addr;
				if(endian32(arp->tpa) == addr) {
					ether->dmac = ether->smac;
					ether->smac = endian48(packet->ni->mac);
					arp->operation = endian16(2);
					arp->tha = arp->sha;
					arp->tpa = arp->spa;
					arp->sha = ether->smac;
					arp->spa = endian32(addr);
					
					ni_output(packet->ni, packet);
					
					return true;
				}
			}
			ni_free(packet);
			return true;
		case 2: // Reply
			;
			uint64_t smac = endian48(arp->sha);
			uint32_t sip = endian32(arp->spa);
			ARPEntity* entity = map_get(arp_table, (void*)(uint64_t)sip);
			if(!entity) {
				entity = __malloc(sizeof(ARPEntity), packet->ni->pool);
				if(!entity)
					goto done;
				
				map_put(arp_table, (void*)(uint64_t)sip, entity);
			}
			entity->mac = smac;
			entity->timeout = current + ARP_TIMEOUT;
			
done:
			ni_free(packet);
			return true;
	} 
	
	return false;
}

bool server_arp_request(NetworkInterface* ni, uint32_t saddr, uint32_t daddr) {
	Packet* packet = ni_alloc(ni, sizeof(Ether) + sizeof(ARP));
	if(!packet)
		return false;
	
	Ether* ether = (Ether*)(packet->buffer + packet->start);
	ether->dmac = endian48(0xffffffffffff);
	ether->smac = endian48(ni->mac);
	ether->type = endian16(ETHER_TYPE_ARP);
	
	ARP* arp = (ARP*)ether->payload;
	arp->htype = endian16(1);
	arp->ptype = endian16(0x0800);
	arp->hlen = endian8(6);
	arp->plen = endian8(4);
	arp->operation = endian16(1);
	arp->sha = endian48(ni->mac);
	arp->spa = endian32(saddr);
	arp->tha = endian48(0);
	arp->tpa = endian32(daddr);
	 
	packet->end = packet->start + sizeof(Ether) + sizeof(ARP);
	
	if(!ni_output(ni, packet)) {
		ni_free(packet);
		return false;
	}
	
	return true;
}

uint64_t server_arp_get_mac(NetworkInterface* ni, uint32_t saddr, uint32_t daddr) {
	Map* arp_table = ni_config_get(ni, ARP_TABLE);
	if(!arp_table) {
		server_arp_request(ni, saddr, daddr);
		return 0xffffffffffff;
	}
	
	ARPEntity* entity = map_get(arp_table, (void*)(uint64_t)daddr);
	if(!entity) {
		server_arp_request(ni, saddr, daddr);
		return 0xffffffffffff;
	}
	
	return entity->mac;
}

bool server_icmp_process(Packet* packet) {
	Ether* ether = (Ether*)(packet->buffer + packet->start);
	if(endian16(ether->type) != ETHER_TYPE_IPv4)
		return false;
	
	List* private_interfaces = ni_config_get(packet->ni, "pn.lb.private_interfaces");
	if(list_is_empty(private_interfaces))
		return false;
	ListIterator iter;
	list_iterator_init(&iter, private_interfaces);
	while(list_iterator_has_next(&iter)) {
		Interface* private_interface = list_iterator_next(&iter);
		IP* ip = (IP*)ether->payload;
		if(ip->protocol == IP_PROTOCOL_ICMP && endian32(ip->destination) == private_interface->addr) {
			ICMP* icmp = (ICMP*)ip->body;
			
			icmp->type = 0;
			icmp->checksum = 0;
			icmp->checksum = endian16(checksum(icmp, packet->end - packet->start - ETHER_LEN - IP_LEN));
			
			swap32(ip->source, ip->destination);
			ip->ttl = endian8(64);
			ip->checksum = 0;
			ip->checksum = endian16(checksum(ip, ip->ihl * 4));
			
			swap48(ether->smac, ether->dmac);
			
			ni_output(packet->ni, packet);
			
			return true;
		}
	}
	
	return false;
}

Server* server_alloc(Interface* server_interface, uint8_t mode) {
	Server* server = (Server*)malloc(sizeof(Server));
	if(server == NULL) {
		printf("Can'nt allocation server\n");
		goto error_server_alloc;
	}

	server->server_interface = server_interface;
	server->state = LB_SERVER_STATE_OK;
	server->mode = mode;
	server->event_id = 0;

 //	server->services = list_create(NULL);
 //	if(server->services == NULL)
 //		goto error_list_create;
	server->sessions = map_create(4096, NULL, NULL, NULL);
	if(server->sessions == NULL)
		goto error_map_create;
		
	return server;

error_map_create:
 //	list_destroy(server->services);
 //error_list_create: free(server);
error_server_alloc:
	return NULL;
}

bool server_free(Server* server) {
 //	ListIterator iter;
 //	list_iterator_init(&iter, server->services);
 //	while(list_iterator_has_next(&iter)) {
 //		Service* service = list_iterator_next(&iter);
 //		list_remove_data(service->servers, server);
 //	}

 //	list_destroy(server->services);
	free(server);

	return true;
}

Server* server_get(NetworkInterface* ni, uint8_t protocol, uint32_t addr, uint16_t port) {
	Map* servers = ni_config_get(ni, "pn.lb.servers");
	uint64_t key = (uint64_t)protocol << 48 | (uint64_t)addr << 16 | (uint64_t)port;
	Server* server = map_get(servers, (void*)key);
	return server;
}

bool server_add(NetworkInterface* ni, Server* server) {
	uint32_t count = ni_count();
	for(int i = 0; i < count; i++) {
		NetworkInterface* service_ni = ni_get(i);
		Service* service = ni_config_get(service_ni, "pn.lb.service");

		if(service == NULL)
			continue;

		Interface* private_interface = map_get(service->private_interfaces, ni);
		if(private_interface == NULL)
			continue;

		list_add(service->servers, server);
	}

	Map* servers = ni_config_get(ni, "pn.lb.servers");
	Interface* server_interface = server->server_interface;

	uint64_t key = (uint64_t)server_interface->protocol << 48 | (uint64_t)server_interface->addr << 16 | (uint64_t)server_interface->port;
	if(!map_put(servers, (void*)key, server)) {
		return false;
	}

	return true;
}

void server_is_remove_grace(Server* server) {
	if(server->state == LB_SERVER_STATE_OK)
		return;

	Map* sessions = ni_config_get(server->server_interface->ni, "pn.lb.sessions");
	if(map_is_empty(sessions)) { //none session //		
		if(server->event_id != 0) {
			event_timer_remove(server->event_id);
			server->event_id = 0;
		}

		//remove from ni
		Interface* server_interface = server->server_interface;
		Map* servers = ni_config_get(server_interface->ni, "pn.lb.servers");
		uint64_t key = (uint64_t)server_interface->protocol << 48 | (uint64_t)server_interface->addr << 16 | (uint64_t)server_interface->port;
		map_remove(servers, (void*)key);

		server_free(server);
	}
}

bool server_remove(Server* server, uint64_t wait) {
	bool server_delete_event(void* context) {
		Server* server = context;
		server_remove_force(server);

		return false;
	}

	Map* sessions = ni_config_get(server->server_interface->ni, "pn.lb.sessions");
	if(map_is_empty(sessions)) {
		server_remove_force(server);
		return true;
	} else {
		server->state = LB_SERVER_STATE_REMOVING;

		if(wait != 0)
			server->event_id = event_timer_add(server_delete_event, server, wait, 0);

		return true;
	}
}

bool server_remove_force(Server* server) {
	if(server->event_id != 0) {
		event_timer_remove(server->event_id);
		server->event_id = 0;
	}

	Map* sessions = ni_config_get(server->server_interface->ni, "pn.lb.sessions");
	if(map_is_empty(sessions)) {
		//delet from ni
		Interface* server_interface = server->server_interface;
		Map* servers = ni_config_get(server_interface->ni, "pn.lb.servers");
		uint64_t key = (uint64_t)server_interface->protocol << 48 | (uint64_t)server_interface->addr << 16 | (uint64_t)server_interface->port;
		map_remove(servers, (void*)key);

		server_free(server);
		return true;
	}

	server->state = LB_SERVER_STATE_REMOVING;
	MapIterator iter;
	map_iterator_init(&iter, sessions);
	while(map_iterator_has_next(&iter)) {
		MapEntry* entry = map_iterator_next(&iter);
		Session* session = entry->data;
		
		session_free(session);
	}

	return true;
}

void server_dump() {
	void print_state(uint8_t state) {
		if(state == LB_SERVER_STATE_OK)
			printf("OK\t\t");
		else if(state == LB_SERVER_STATE_REMOVING)
			printf("Removing\t");
		else
			printf("Unnowkn\t");
	}
	void print_mode(uint8_t mode) {
		if(mode == LB_MODE_NAT)
			printf("NAT\t");
		else if(mode == LB_MODE_DNAT)
			printf("DNAT\t");
		else if(mode == LB_MODE_DR)
			printf("DR\t");
		else
			printf("Unnowkn\t");
	}
	void print_addr_port(uint32_t addr, uint16_t port) {
		printf("%d.%d.%d.%d:%d\t", (addr >> 24) & 0xff, (addr >> 16) & 0xff,
				(addr >> 8) & 0xff, addr & 0xff, port);
	}
	void print_ni_num(uint8_t ni_num) {
		printf("%d\t", ni_num);
	}
	void print_session_count(Map* sessions) {
		printf("%d\t", map_size(sessions));
	}

	printf("State\t\tAddr:Port\t\tMode\tNIC\tSessions\n");
	uint8_t count = ni_count();
	for(int i = 0; i < count; i++) {
		Map* servers = ni_config_get(ni_get(i), "pn.lb.servers");
		MapIterator iter;
		map_iterator_init(&iter, servers);
		while(map_iterator_has_next(&iter)) {
			MapEntry* entry = map_iterator_next(&iter);
			Server* server = entry->data;
			if(server == NULL)
				continue;

			print_state(server->state);
			print_addr_port(server->server_interface->addr, server->server_interface->port);
			print_mode(server->mode);
			print_ni_num(server->server_interface->ni_num);
			Map* sessions = ni_config_get(server->server_interface->ni, "pn.lb.sessions");
			print_session_count(sessions);
			printf("\n");
		}
	}
}
