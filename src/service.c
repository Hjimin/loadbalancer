#include <stdio.h>
#include <malloc.h>
#define DONT_MAKE_WRAPPER
#include <_malloc.h>
#undef DONT_MAKE_WRAPPER
#include <util/event.h>
#include <net/ether.h>
#include <net/ni.h>
#include <net/ip.h>
#include <net/arp.h>

#include "server.h"
#include "session.h"
#include "service.h"

#define ARP_TABLE	"net.arp.arptable"
#define ARP_TABLE_GC	"net.arp.arptable.gc"

#define GC_INTERVAL	(10 * 1000000)	// 10 secs

typedef struct {
	uint64_t	mac;
	uint64_t	timeout;
} ARPEntity;

bool service_arp_process(Packet* packet) {
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
		case 1:;	// Request
			Map* services = ni_config_get(packet->ni, "pn.lb.services");
			if(map_is_empty(services))
				return false;

			MapIterator iter;
			map_iterator_init(&iter, services);
			while(map_iterator_has_next(&iter)) {
				MapEntry* entry = map_iterator_next(&iter);
				Service* service = entry->data;

				if(endian32(arp->tpa) == service->addr) {
					ether->dmac = ether->smac;
					ether->smac = endian48(packet->ni->mac);
					arp->operation = endian16(2);
					arp->tha = arp->sha;
					arp->tpa = arp->spa;
					arp->sha = ether->smac;
					arp->spa = endian32(service->addr);
					
					ni_output(packet->ni, packet);
					ni_free(packet);
					
					return true;
				}
			}
			break;
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

static Service* service_alloc(uint8_t protocol, uint32_t addr, uint16_t port, uint8_t schedule, uint8_t ni_num, uint64_t timeout) {
	Service* service = (Service*)malloc(sizeof(Service));
	if(service == NULL) {
		printf("Can'nt found Service\n");
		goto error_service_alloc;
	}

	service->state = LB_SERVICE_STATE_OK;
	service->protocol = protocol;
	service->addr = addr;
	service->port = port;

	service->robin = 0;
	service->schedule = schedule;
	service->timeout = timeout;
	service->servers = list_create(NULL);
	if(service->servers == NULL) {
		printf("Can'nt create Server list\n");
		goto error_servers_alloc;
	}

	service->sessions = map_create(4096, NULL, NULL, NULL);
	if(service->sessions == NULL) {
		printf("Can'nt create Session map\n");
		goto error_sessions_alloc;
	}

	service->ni_num = ni_num;
	NetworkInterface* ni = ni_get(ni_num);
	if(ni == NULL) {
		printf("Can'nt found Network Interface\n");
		goto error_ni_not_found;
	}
	service->ni = ni;

	Map* services = ni_config_get(ni, "pn.lb.services");
	if(services == NULL) {
		printf("Can'nt found services\n");
		goto error_services_not_found;
	}

	if(!map_put(services, (void*)((uint64_t)protocol << 48 | (uint64_t)addr << 16 | port), service)) {
		printf("Can'nt add service\n");
		goto error_can_not_add_service;
	}

	return service;

error_can_not_add_service:
error_services_not_found:
error_ni_not_found:
	if(service->sessions != NULL)
		free(service->sessions);

error_sessions_alloc:
	if(service->servers != NULL)
		free(service->servers);

error_servers_alloc:
	if(service != NULL)
		free(service);

error_service_alloc:

	return NULL;
}

static bool service_free(Service* service) {
	list_destroy(service->servers);
	map_destroy(service->sessions);
	free(service);

	return true;
}

Service* find_service(NetworkInterface* ni, uint8_t protocol, uint32_t addr, uint16_t port) {
	Map* services = ni_config_get(ni, "pn.lb.services");
	if(services == NULL) {
		printf("Can'nt found services: find_service\n");
		return NULL;
	}

	return map_get(services, (void*)((uint64_t)protocol << 48 | (uint64_t)addr << 16 | (uint64_t)port));
}

bool service_add(uint8_t protocol, uint32_t addr, uint16_t port, uint8_t schedule, uint8_t ni_num, uint64_t timeout) {
	NetworkInterface* ni = ni_get(ni_num);
	if(ni == NULL) {
		printf("Can'nt found NI\n");
		return false;
	}

	if(find_service(ni, protocol, addr, port) != NULL) {
		printf("Can'nt found service\n");
		return false;
	}

	Service* service = service_alloc(protocol, addr, port, schedule, ni_num, timeout);

	if(service == NULL) {
		printf("Can'nt add Service\n");
		return false;
	}

	return true;
}

bool service_is_empty(NetworkInterface* ni) {
	Map* services = ni_config_get(ni, "pn.lb.services");

	if(services == NULL) {
		printf("Can'nt found services\n");
		return true;
	}

	if(map_is_empty(services))
		return true;
	else
		return false;
}

void service_is_remove_grace(Service* service) {
	if(service->state == LB_SERVICE_STATE_OK)
		return;

	if(map_is_empty(service->sessions)) { //none session
		if(service->event_id != 0)
			event_timer_remove(service->event_id);

		//Remove all server in service
		List* list = service->servers;
		ListIterator iter;
		list_iterator_init(&iter, list);
		while(list_iterator_has_next(&iter)) {
			Server* server = list_iterator_remove(&iter);

			Map* servers = ni_config_get(server->ni, "pn.lb.servers");
			if(servers == NULL) {
				printf("Can'nt found servers\n");
				continue;
			}
			if(!map_remove(servers, (void*)((uint64_t)server->protocol << 48 | (uint64_t)server->addr << 16 | (uint64_t)server->port)))
				printf("Can'nt remove servers\n");

			server_free(server);
		}

		Map* services = ni_config_get(service->ni, "pn.lb.services");
		if(!map_remove(services, (void*)((uint64_t)service->protocol << 48 | (uint64_t)service->addr << 16 | (uint64_t)service->port)))
			printf("Can'nt remove service\n");
		service_free(service);
	}
}

bool service_remove(uint8_t protocol, uint32_t addr, uint16_t port, uint8_t ni_num, uint64_t wait) {
	bool service_delete_event(void* context) {
		Service* service = context;
		NetworkInterface* ni = service->ni;
		if(map_is_empty(service->sessions)) { //none session
			//Remove all server in service
			List* list = service->servers;
			ListIterator iter;
			list_iterator_init(&iter, list);
			while(list_iterator_has_next(&iter)) {
				Server* server = list_iterator_remove(&iter);
				//remove from ni
				server_free(server);
			}

			Map* services = ni_config_get(ni, "pn.lb.services");
			map_remove(services, (void*)((uint64_t)protocol << 48 | (uint64_t)addr << 16 | (uint64_t)port));
			service_free(service);

		} else {
			service_remove_force(service->protocol, service->addr, service->port, service->ni_num);
		}

		return false;
	}

	NetworkInterface* ni = ni_get(ni_num);
	if(ni == NULL) {
		printf("Can'nt found Network Interface\n");
		return false;
	}

	Service* service = find_service(ni, protocol, addr, port);
	if(!service) {
		printf("Can'nt found Service\n");
		return false;
	}

	if(map_is_empty(service->sessions)) { //none session
		//Remove all server in service
		List* list = service->servers;
		ListIterator iter;
		list_iterator_init(&iter, list);
		while(list_iterator_has_next(&iter)) {
			Server* server = list_iterator_remove(&iter);
			server_free(server);
		}

		Map* services = ni_config_get(ni, "pn.lb.services");
		map_remove(services, (void*)((uint64_t)protocol << 48 | (uint64_t)addr << 16 | (uint64_t)port));
		service_free(service);

		return true;
	} else {
		service->state = LB_SERVICE_STATE_REMOVING;

		if(wait) {
			service->state = LB_SERVICE_STATE_REMOVING;
			service->event_id = event_timer_add(service_delete_event, service, wait, 0);
		}

		return true;
	}
}

bool service_remove_force(uint8_t protocol, uint32_t addr, uint16_t port, uint8_t ni_num) {
	NetworkInterface* ni = ni_get(ni_num);
	if(ni == NULL) {
		printf("Can'nt found Network Interface\n");
		return false;
	}

	Service* service = find_service(ni, protocol, addr, port);
	if(!service) {
		printf("Can'nt found Service\n");
		return false;
	}

	//Remove all server in service
	List* servers = service->servers;
	ListIterator servers_iter;
	list_iterator_init(&servers_iter, servers);
	while(list_iterator_has_next(&servers_iter)) {
		Server* server = list_iterator_remove(&servers_iter);
		server_free(server);
	}

	//Remove all sessions in services
	Map* sessions = service->sessions;
	MapIterator sessions_iter;
	map_iterator_init(&sessions_iter, sessions);
	while(map_iterator_has_next(&sessions_iter)) {
		MapEntry* entry = map_iterator_remove(&sessions_iter);
		Session* session = entry->data;

		if(session->event_id != 0)
			event_timer_remove(session->event_id);

		session_free(session);
	}

	//Remove service
	Map* services = ni_config_get(ni, "pn.lb.services");
	map_remove(services, (void*)((uint64_t)protocol << 48 | (uint64_t)addr << 16 | (uint64_t)port));
	service_free(service);

	return true;
}

void service_dump() {
	void print_state(uint8_t state) {
		if(state == LB_SERVICE_STATE_OK)
			printf("OK\t\t");
		else if(state == LB_SERVICE_STATE_REMOVING)
			printf("Removing\t");
		else
			printf("Unnowkn\t");
	}
	void print_protocol(uint8_t protocol) {
		if(protocol == IP_PROTOCOL_TCP)
			printf("TCP\t\t");
		else if(protocol == IP_PROTOCOL_UDP)
			printf("UDP\t\t");
		else
			printf("Unnowkn\t");
	}
	void print_addr_port(uint32_t addr, uint16_t port) {
		printf("%d.%d.%d.%d:%d\t", (addr >> 24) & 0xff, (addr >> 16) & 0xff,
				(addr >> 8) & 0xff, addr & 0xff, port);
	}
	void print_schedule(uint8_t schedule) {
		if(schedule == LB_SCHEDULE_ROUND_ROBIN) {
			printf("Round-Robin\t");
		} else
			printf("Unnowkn\t");
	}
	void print_ni_num(uint8_t ni_num) {
		printf("%d\t", ni_num);
	}
	void print_session_count(Map* sessions) {
		printf("%d\t", map_size(sessions));
	}


	printf("State\t\tProtocol\tAddr:Port\t\tSchedule\tNIC\tSession\n");
	int count = ni_count();
	for(int i = 0; i < count; i++) {
		NetworkInterface* ni = ni_get(i);
		if(ni == NULL)
			continue;
		Map* services = ni_config_get(ni, "pn.lb.services");
		if(services == NULL) {
			printf("Can'nt found services");
			continue;
		}

		MapIterator iter;
		map_iterator_init(&iter, services);
		while(map_iterator_has_next(&iter)) {
			MapEntry* entry = map_iterator_next(&iter);
			Service* service = entry->data;
			if(service == NULL) {
				printf("Can'nt found service");
				continue;
			}
				
			print_state(service->state);
			print_protocol(service->protocol);
			print_addr_port(service->addr, service->port);
			print_schedule(service->schedule);
			print_ni_num(service->ni_num);
			print_session_count(service->sessions);
			printf("\n");
		}
	}
}

