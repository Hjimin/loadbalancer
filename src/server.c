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

Server* server_alloc(Interface* server_interface, Interface* private_interface, uint8_t mode) {
	Server* server = (Server*)malloc(sizeof(Server));
	if(server == NULL) {
		printf("Can'nt allocation server\n");
		goto error_server_alloc;
	}

	server->server_interface = server_interface;
	server->private_interface = private_interface;
	server->state = LB_SERVER_STATE_OK;
	server->mode = mode;
	server->event_id = 0;

	server->services = list_create(NULL);
	if(server->services == NULL)
		goto error_list_create;

		
	return server;

error_list_create:
	free(server);

error_server_alloc:
	return NULL;
}

bool server_free(Server* server) {
	ListIterator iter;
	list_iterator_init(&iter, server->services);
	while(list_iterator_has_next(&iter)) {
		Service* service = list_iterator_next(&iter);
		list_remove_data(service->servers, server);
	}

	list_destroy(server->services);
	free(server);

	return true;
}

Server* server_get(NetworkInterface* ni) {
	return ni_config_get(ni, "pn.lb.server");
}

bool server_add(NetworkInterface* ni, Server* server) {
	uint32_t count = ni_count();
	for(int i = 0; i < count; i++) {
		NetworkInterface* service_ni = ni_get(i);
		Service* service = ni_config_get(service_ni, "pn.lb.service");

		if(service == NULL)
			continue;

		ListIterator list_iter;
		list_iterator_init(&list_iter, service->server_nis);
		while(list_iterator_has_next(&list_iter)) {
			NetworkInterface* server_ni = list_iterator_next(&list_iter);
			if(server_ni == ni) {
				list_add(service->servers, server);
			}
		}
	}

	ni_config_put(ni, "pn.lb.server", server);
	ni_config_put(ni, "ip", (void*)(uint64_t)server->private_interface->addr);

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
		ni_config_remove(server_interface->ni, "pn.lb.server");

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
		ni_config_remove(server_interface->ni, "pn.lb.server");

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
		Server* server = ni_config_get(ni_get(i), "pn.lb.server");
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
