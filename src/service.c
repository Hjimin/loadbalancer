#include <stdio.h>
#include <malloc.h>
#include <util/event.h>
#include <net/ether.h>
#include <net/ni.h>
#include <net/ip.h>
#include <net/arp.h>

#include "interface.h"
#include "server.h"
#include "session.h"
#include "service.h"

static Service* service_alloc(Interface* public_interface, uint8_t schedule, Interface* private_interfaces, uint8_t private_interface_count) {
	Service* service = (Service*)malloc(sizeof(Service));
	if(service == NULL) {
		printf("Can'nt found Service\n");
		goto error_service_alloc;
	}

	service->public_interface = interface;
	service->schedule = schedule;
	service->timeout = DEFAULT_TIMEOUT;
	service->state = LB_SERVICE_STATE_OK;

	service->private_interfaces = list_create(NULL);
	if(service->private_interface == NULL) {
		printf("Can'nt create NetworkInterface Out List\n");
		goto error_create_ni_out_list;
	}
	for(int i = 0 ; i < private_count; i++) {
		list_add(service->private_interfaces, private_interfaces[i]);
	}

	return service;

free_interface:
	if(interface != NULL)
		interface_delete(interface);

error_service_alloc:
	if(service != NULL)
		free(service);

	return NULL;
}

static bool service_free(Service* service) {
	if(!map_is_empty(service->sessions)) {
		printf("Session is not empty\n");
		return false;
	}
	map_destroy(service->sessions);
	free(service);

	return true;
}

bool service_add(uint8_t protocol, uint32_t addr, uint16_t port, uint8_t schedule, uint8_t ni_in, uint8_t* ni_out, uint8_t ni_out_count) {
	NetworkInterface* ni = ni_get(ni_in);
	if(ni == NULL) {
		printf("NetworkInterface not found\n");
		return false;
	}
	if(service_found(ni, protocol, addr, port) != NULL) {
		printf("Already service exist\n");
		return false;
	}

	Service* service = service_alloc(protocol, addr, port, schedule, ni_in, ni_out, ni_out_count);
	if(service == NULL) {
		printf("Can'nt add Service\n");
		return false;
	}

	return true;
}

bool service_is_empty(NetworkInterface* ni) {
	Map* services = ni_config_get(ni, "pn.lb.services");

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

		service_remove_force(service);
	}
}

Service* service_found(NetworkInterface* ni, uint8_t protocol, uint32_t addr, uint16_t port) {
	Map* services = ni_config_get(ni, "pn.lb.services");

	return map_get(services, (void*)((uint64_t)protocol << 48 | (uint64_t)addr << 16 | (uint64_t)port));
}

bool service_remove(Service* service, uint64_t wait) {
	bool service_delete_event(void* context) {
		service_remove_force(service);

		return false;
	}

	if(map_is_empty(service->sessions)) { //none session
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

	if(map_is_empty(service->sessions)) {
		Map* services = ni_config_get(service->ni, "pn.lb.services");
		if(!map_remove(services, (void*)((uint64_t)service->protocol << 48 | (uint64_t)service->addr << 16 | (uint64_t)service->port)))
			printf("Can'nt remove service\n");
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
			print_ni_num(service->ni_in);
			print_session_count(service->sessions);
			printf("\n");
		}
	}
}

