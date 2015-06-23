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
#include <errno.h>

#include "interface.h"
#include "server.h"
#include "session.h"
#include "service.h"

static Server* schedule_random(Service* service);
static Server* schedule_round_robin(Service* service);

Service* service_alloc(Interface* service_interface, uint8_t* out_port, uint8_t out_port_count, uint8_t schedule) {
	Service* service = (Service*)malloc(sizeof(Service));
	if(service == NULL) {
		//printf("Can'nt found Service\n");
		errno = SERVICE_ALLOCATE_FAIL;
		goto error_service_alloc;
	}

	service->service_interface = service_interface;
 //	service->private_interfaces = list_create(NULL);
 //	if(service->private_interfaces == NULL) {
 //		//printf("Can'nt create NetworkInterface Out List\n");
 //		errno = SERVICE_LIST_CREATE_FAIL;
 //		goto error_create_private_interface_list;
 //	}
 //	for(int i = 0; i < private_interface_count; i++) {
 //		list_add(service->private_interfaces, private_interfaces[i]);
 //	}
	switch(schedule) {
		case LB_SCHEDULE_ROUND_ROBIN:
			service->get_server = schedule_round_robin;
			break;
		case LB_SCHEDULE_RANDOM:
			service->get_server = schedule_random;
			break;
		default:
			errno = -2;
			goto error_schedule;
	}
	service->schedule = schedule;
	service->robin = 0;
	service->timeout = LB_SERVICE_DEFAULT_TIMEOUT;
	service->state = LB_SERVICE_STATE_OK;

	service->server_nis = list_create(NULL);
	service->servers = list_create(NULL);
	if(service->servers == NULL) {
		errno = -SERVICE_LIST_CREATE_FAIL;
		goto error_create_list;
	}
	for(int i = 0 ; i < out_port_count; i++) {
		NetworkInterface *ni = ni_get(out_port[i]);
		if(ni == NULL) {
			printf("Can'nt found NetworkInterface\n");
			errno = -3;
			goto error_create_server_list;
		}
		list_add(service->server_nis, ni);
		Server* server = ni_config_get(ni, "pn.lb.server");
		if(server == NULL)
			continue;

		list_add(service->servers, server);
		list_add(server->services, service);
	}

	return service;

error_schedule:
error_create_server_list:
	list_destroy(service->servers);

error_create_list:
	free(service);

error_service_alloc:

	return NULL;
}

static bool service_free(Service* service) {
	//delete from server
	ListIterator iter;
	list_iterator_init(&iter, service->servers);
	while(list_iterator_has_next(&iter)) {
		Server* server = list_iterator_next(&iter);
		list_remove_data(server->services, service);
	}

	list_destroy(service->servers);
	free(service);

	return true;
}

bool service_add(NetworkInterface* ni, Service* service) {
	ni_config_put(ni, "pn.lb.service", service);
	ni_config_put(ni, "ip", (void*)(uint64_t)service->service_interface->addr);

	return true;
}

Service* service_get(NetworkInterface* ni) {
	return ni_config_get(ni, "pn.lb.service");
}

void service_is_remove_grace(Service* service) {
	if(service->state == LB_SERVICE_STATE_OK)
		return;

	Map* sessions = ni_config_get(service->service_interface->ni, "pn.lb.sessions");
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

	Map* sessions = ni_config_get(service->service_interface->ni, "pn.lb.sessions");
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

	Map* sessions = ni_config_get(service->service_interface->ni, "pn.lb.sessions");
	if(map_is_empty(sessions)) {
		Interface* service_interface = service->service_interface;
		ni_config_remove(service_interface->ni, "pn.lb.service");
		service_free(service);
	}

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
	void print_server_count(List* servers) {
		printf("%d\t", list_size(servers));
	}


	printf("State\t\tProtocol\tAddr:Port\t\tSchedule\tNIC\tSession\tServer\n");
	int count = ni_count();
	for(int i = 0; i < count; i++) {
		NetworkInterface* ni = ni_get(i);
		if(ni == NULL)
			continue;
		Service* service = ni_config_get(ni, "pn.lb.service");
		if(service == NULL) {
			printf("Can'nt found service");
			continue;
		}
			
		print_state(service->state);
		print_protocol(service->service_interface->protocol);
		print_addr_port(service->service_interface->addr, service->service_interface->port);
		print_schedule(service->schedule);
		print_ni_num(service->service_interface->ni_num);
		Map* sessions = ni_config_get(service->service_interface->ni, "pn.lb.sessions");
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
