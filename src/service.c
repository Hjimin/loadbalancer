#include <stdio.h>
#include <malloc.h>
#include <util/event.h>
#include <util/map.h>
#include <net/ni.h>
#include <net/ether.h>
#include <net/icmp.h>
#include <net/checksum.h>
#include <net/ip.h>
#include <net/arp.h>

#include "interface.h"
#include "server.h"
#include "session.h"
#include "service.h"

static Server* schedule_round_robin(Service* service);
static Server* schedule_random(Service* service);
static Server* schedule_min(Service* service);

Service* service_alloc(Interface* service_interface, Interface** private_interfaces, uint8_t private_interface_count, uint8_t schedule) {
	Service* service = (Service*)malloc(sizeof(Service));
	if(service == NULL) {
		goto error_service_alloc;
	}

	service->service_interface = service_interface;
	switch(schedule) {
		case LB_SCHEDULE_ROUND_ROBIN:
			service->get_server = schedule_round_robin;
			break;
		case LB_SCHEDULE_RANDOM:
			service->get_server = schedule_random;
			break;
		case LB_SCHEDULE_MIN:
			service->get_server = schedule_min;
			break;
		default:
			goto error_schedule;
	}
	service->schedule = schedule;
	service->robin = 0;
	service->timeout = LB_SERVICE_DEFAULT_TIMEOUT;
	service->state = LB_SERVICE_STATE_OK;

	service->private_interfaces = map_create(4096, NULL, NULL, NULL);
	if(service->private_interfaces == NULL)
		goto error_create_map;

	service->servers = list_create(NULL);
	if(service->servers == NULL)
		goto error_create_list;

	for(int i = 0 ; i < private_interface_count; i++) {
		NetworkInterface* ni = private_interfaces[i]->ni;
		map_put(service->private_interfaces, ni, private_interfaces[i]);

		List* _private_interfaces = ni_config_get(ni, PN_LB_PRIVATE_INTERFACES);
		list_add(_private_interfaces, private_interfaces[i]);

		Map* servers = ni_config_get(ni, PN_LB_SERVERS);
		if(map_is_empty(servers))
			continue;

		MapIterator iter;
		map_iterator_init(&iter, servers);
		while(map_iterator_has_next(&iter)) {
			MapEntry* entry = map_iterator_next(&iter);
			Server* server = entry->data;
			list_add(service->servers, server);
		}
	}

	return service;

error_create_list:
	if(service->private_interfaces != NULL)
		map_destroy(service->private_interfaces);

error_create_map:
	free(service);
error_schedule:

error_service_alloc:

	return NULL;
}

static bool service_free(Service* service) {
	map_destroy(service->private_interfaces);
	list_destroy(service->servers);
	free(service);

	return true;
}

bool service_add(NetworkInterface* ni, Service* service) {
	ni_config_put(ni, PN_LB_SERVICE, service);
	ni_config_put(ni, "ip", (void*)(uint64_t)service->service_interface->addr);

	return true;
}

Service* service_get(NetworkInterface* ni) {
	return ni_config_get(ni, PN_LB_SERVICE);
}

void service_is_remove_grace(Service* service) {
	if(service->state == LB_SERVICE_STATE_OK)
		return;

	Map* sessions = ni_config_get(service->service_interface->ni, PN_LB_SESSIONS);
	if(map_is_empty(sessions)) { //none session
		if(service->event_id != 0)
			event_timer_remove(service->event_id);

		service_remove_force(service);
	}
}

bool service_remove(Service* service, uint64_t wait) {
	bool service_delete_event(void* context) {
		service_remove_force(service);

		return false;
	}

	Map* sessions = ni_config_get(service->service_interface->ni, PN_LB_SESSIONS);
	if(map_is_empty(sessions)) { //none session
		service_remove_force(service);

		return true;
	} else {
		service->state = LB_SERVICE_STATE_REMOVING;

		if(wait) {
			service->event_id = event_timer_add(service_delete_event, service, wait, 0);
		}

		return true;
	}
}

bool service_remove_force(Service* service) {
	if(service->event_id != 0) {
		event_timer_remove(service->event_id);
		service->event_id = 0;
	}

	service->state = LB_SERVICE_STATE_REMOVING;

	Map* sessions = ni_config_get(service->service_interface->ni, PN_LB_SESSIONS);
	if(!map_is_empty(sessions)) {
	}

	Map* private_interfaces = service->private_interfaces;
	MapIterator iter;
	map_iterator_init(&iter, private_interfaces);
	while(map_iterator_has_next(&iter)) {
		MapEntry* entry = map_iterator_next(&iter);
		Interface* private_interface = entry->data;
		NetworkInterface* ni = private_interface->ni;
		List* _private_interfaces = ni_config_get(ni, PN_LB_PRIVATE_INTERFACES);
		list_remove_data(_private_interfaces, private_interface);
	}

	Interface* service_interface = service->service_interface;
	ni_config_remove(service_interface->ni, PN_LB_SERVICE);
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
		switch(schedule) {
			case LB_SCHEDULE_ROUND_ROBIN:
				printf("Round-Robin\t");
				break;
			case LB_SCHEDULE_RANDOM:
				printf("Random\t\t");
				break;
			default:
				printf("Unnowkn\t");
				break;
		}
	}
	void print_ni_num(uint8_t ni_num) {
		printf("%d\t", ni_num);
	}
	void print_session_count(Map* sessions) {
		printf("%d\t", map_size(sessions));
	}
	void print_server_count(List* servers) {
		printf("%d\t", list_size(servers));
	}


	printf("State\t\tProtocol\tAddr:Port\t\tSchedule\tNIC\tSession\tServer\n");
	int count = ni_count();
	for(int i = 0; i < count; i++) {
		NetworkInterface* ni = ni_get(i);
		if(ni == NULL)
			continue;
		Service* service = ni_config_get(ni, PN_LB_SERVICE);
		if(service == NULL) {
			continue;
		}
			
		print_state(service->state);
		print_protocol(service->service_interface->protocol);
		print_addr_port(service->service_interface->addr, service->service_interface->port);
		print_schedule(service->schedule);
		print_ni_num(service->service_interface->ni_num);
		Map* sessions = ni_config_get(service->service_interface->ni, PN_LB_SESSIONS);
		print_session_count(sessions);
		print_server_count(service->servers);
		printf("\n");
	}
}

static Server* schedule_round_robin(Service* service) {
	uint32_t count = list_size(service->servers);
	if(count == 0)
		return NULL; 

	uint32_t index = (service->robin++) % count;

	Server* server = list_get(service->servers, index);
	while(server->state != LB_SERVER_STATE_OK) {
		uint32_t _index = (service->robin++) % count;
		if(index == _index)
			return NULL;

		server = list_get(service->servers, _index);
	}
	return server;
}

static Server* schedule_random(Service* service) {
	inline uint64_t cpu_tsc() {
		uint64_t time;
		uint32_t* p = (uint32_t*)&time;
		asm volatile("rdtsc" : "=a"(p[0]), "=d"(p[1]));
		
		return time;
	}

	uint32_t count = list_size(service->servers);
	if(count == 0)
		return NULL;

	uint32_t random_num = cpu_tsc() % count;

	Server* server = list_get(service->servers, random_num);
	while(server->state != LB_SERVER_STATE_OK) {
		uint32_t _random_num = cpu_tsc() % count;
		if(random_num == _random_num)
			return NULL;

		server = list_get(service->servers, _random_num);
	}
	return server;
}

static Server* schedule_min(Service* service) {
	uint32_t count = list_size(service->servers);
	if(count == 0)
		return NULL; 

	List* servers = service->servers;
	ListIterator iter;
	list_iterator_init(&iter, servers);
	Server* server = NULL;
	uint32_t session_count = UINT32_MAX;
	while(list_iterator_has_next(&iter)) {
		Server* _server = list_iterator_next(&iter);

		if(_server->state != LB_SERVER_STATE_OK)
			continue;

		if(map_size(_server->sessions) < session_count)
			server = _server;
	}

	return server;
}
