#include <stdio.h>
#include <malloc.h>
#include <util/event.h>
#include <net/ether.h>
#include <net/icmp.h>
#include <net/checksum.h>
#include <net/ip.h>
#include <net/arp.h>

#include "service.h"
#include "interface.h"
#include "server.h"
#include "session.h"
#include "schedule.h"

extern void* __gmalloc_pool;
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
		case LB_SCHEDULE_LEAST:
			service->get_server = schedule_least;
			break;
		case LB_SCHEDULE_SOURCE_IP_HASH:
			service->get_server = schedule_source_ip_hash;
			break;
		case LB_SCHEDULE_WEIGHTED_ROUND_ROBIN:
			service->get_server = schedule_weighted_round_robin;
			break;
		default:
			goto error_schedule;
	}
	service->schedule = schedule;
	service->robin = 0;
	service->timeout = LB_SERVICE_DEFAULT_TIMEOUT;
	service->state = LB_SERVICE_STATE_OK;

	service->private_interfaces = map_create(16, NULL, NULL, __gmalloc_pool);
	if(!service->private_interfaces)
		goto error_create_map;

	service->enable_servers = list_create(NULL);
	if(!service->enable_servers)
		goto error_create_enable_servers_list;

	service->disable_servers = list_create(NULL);
	if(!service->disable_servers)
		goto error_create_disable_servers_list;

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
			if(server->state == LB_SERVER_STATE_OK)
				list_add(service->enable_servers, server);
			else if(server->state == LB_SERVER_STATE_REMOVING)
				list_add(service->disable_servers, server);
		}
	}

	return service;

error_create_disable_servers_list:
	list_destroy(service->enable_servers);

error_create_enable_servers_list:
	map_destroy(service->private_interfaces);

error_create_map:
	free(service);
error_schedule:

error_service_alloc:

	return NULL;
}

static bool service_free(Service* service) {
	map_destroy(service->private_interfaces);
	list_destroy(service->enable_servers);
	list_destroy(service->disable_servers);
	free(service);

	return true;
}

Session* service_get_session(NetworkInterface* ni, uint8_t protocol, uint32_t saddr, uint16_t sport) {
	Map* sessions = ni_config_get(ni, PN_LB_SESSIONS);
	Session* session = map_get(sessions, (void*)((uint64_t)protocol << 48 | (uint64_t)saddr << 16 | (uint64_t)sport));

	if(session)
		session_recharge(session);

	return session;
}


Session* service_alloc_session(NetworkInterface* ni, uint8_t protocol, uint32_t saddr, uint16_t sport, uint32_t daddr, uint16_t dport) {
	Service* service = service_get(ni);
	if(!service)
		return NULL;

	Interface* service_interface = service->service_interface;
	if(!((protocol == service_interface->protocol) && (daddr == service_interface->addr) && (dport == service_interface->port)))
		return NULL;

	if(service->state != LB_SERVICE_STATE_OK)
		return NULL;

	Interface* client_interface = interface_create(protocol, saddr, sport, service->service_interface->ni_num);
	if(!client_interface) {
		printf("Interface create error\n");
		return NULL;
	}

	Server* server = service->get_server(service, client_interface);
	if(!server)
		goto error_get_server;

	Session* session = server->get_session(server, service->private_interfaces, service->service_interface, client_interface);
	if(!session)
		goto error_get_session;

	Map* sessions = ni_config_get(service->service_interface->ni, PN_LB_SESSIONS);
	uint64_t key1 = (uint64_t)protocol << 48 | (uint64_t)saddr << 16 | (uint64_t)sport;
	if(!map_put(sessions, (void*)key1, session))
		goto error_session_map_put1;

	sessions = ni_config_get(server->server_interface->ni, PN_LB_SESSIONS);
	uint64_t key2;
	if(server->mode == LB_MODE_NAT)
		key2 = (uint64_t)session->private_interface->protocol << 48 | (uint64_t)session->private_interface->addr << 16 | (uint64_t)session->private_interface->port;
	else
		key2 = (uint64_t)protocol << 48 | (uint64_t)saddr << 16 | (uint64_t)sport;

	if(!map_put(sessions, (void*)key2, session))
		goto error_session_map_put2;

	if(!map_put(server->sessions, (void*)key2, session))
		goto error_session_map_put3;

	session->fin = false;
	session->event_id = 0;
	session_recharge(session);

	return session;

error_session_map_put3:
	map_remove(sessions, (void*)key2);

error_session_map_put2:
	sessions = ni_config_get(service->service_interface->ni, PN_LB_SESSIONS);
	map_remove(sessions, (void*)key1);

error_session_map_put1:
	if(session->private_interface)
		interface_delete(session->private_interface);

error_get_session:
error_get_server:
	interface_delete(client_interface);

	return NULL;
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
	bool service_delete0_event(void* context) {
		Map* sessions = ni_config_get(service->service_interface->ni, PN_LB_SESSIONS);
		if(map_is_empty(sessions)) { //none session
			service_remove_force(service);

			return true;
		}

		return false;
	}

	Map* sessions = ni_config_get(service->service_interface->ni, PN_LB_SESSIONS);
	if(map_is_empty(sessions)) { //none session
		service_remove_force(service);

		return true;
	} else {
		service->state = LB_SERVICE_STATE_REMOVING;

		if(wait)
			service->event_id = event_timer_add(service_delete_event, service, wait, 0);
		else
			service->event_id = event_timer_add(service_delete0_event, service, 1000000, 1000000);

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
		printf("%d", list_size(servers));
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
		print_server_count(service->enable_servers);
		printf(" \040 ");
		print_server_count(service->disable_servers);
		printf("\n");
	}
}
