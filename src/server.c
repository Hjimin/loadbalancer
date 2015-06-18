#include <stdio.h>
#include <stdbool.h>
#include <malloc.h>
#include <util/event.h>

#include "service.h"
#include "session.h"
#include "server.h"

Server* server_alloc(Service* service) {
	uint16_t server_count = list_size(service->servers);
	if(!server_count)
		return NULL;

	List* servers = service->servers;
	int idx = (service->robin++) % server_count;
	Server* server = list_get(servers, idx);
	if(server->state == LB_SERVER_STATE_OK) {
		return server;
	} else {
		while(1) {
			int _idx = (service->robin++) % server_count;
			if(_idx == idx)
				return NULL;

			Server* server = list_get(servers, _idx);
			if(server->state == LB_SERVER_STATE_OK)
				return server;
		}
	}
}

bool server_free(Server* server) {
	map_destroy(server->sessions);
	free(server);

	return true;
}

bool server_is_empty(NetworkInterface* ni) {
	Map* servers = ni_config_get(ni, "pn.lb.servers");

	if(servers == NULL) {
		return true;
	}

	if(map_is_empty(servers))
		return true;
	else
		return false;
}

bool server_add(uint8_t protocol, uint32_t service_addr, uint16_t service_port, uint8_t service_ni_num, uint32_t server_addr, uint16_t server_port, uint8_t mode, uint8_t ni_num) {
	Server* server_alloc(uint8_t protocol, uint32_t addr, uint16_t port, uint8_t mode, uint8_t ni_num) {
		Server* server = (Server*)malloc(sizeof(Server));
		if(server == NULL) {
			printf("Can'nt allocation server\n");
			goto error_server_alloc;
		}

		server->state = LB_SERVER_STATE_OK;
		server->protocol = protocol;
		server->addr = addr;
		server->port = port;
		server->mode = mode;
		server->ni_num = ni_num;
		server->ni = ni_get(ni_num);
		if(server->ni == NULL) {
			printf("Can'nt found Network Interface\n");
			goto error_ni_not_found;
		}
		server->sessions = map_create(4096, NULL, NULL, NULL);
		if(server->sessions == NULL) {
			printf("Can'nt create Session map\n");
			goto error_sessions_alloc;
		}

		return server;

	error_sessions_alloc:
		if(server != NULL)
			free(server);

	error_ni_not_found:
	error_server_alloc:

		return NULL;
	}

	Service* service = find_service(ni_get(service_ni_num), protocol, service_addr, service_port);
	if(service == NULL) { 
		printf("Can'nt found service\n");
		return false;
	}

	Server* server = server_alloc(protocol, server_addr, server_port, mode, ni_num);
	server->service = service;
	if(server == NULL) {
		printf("Can'nt create server\n");
		return false;
	}
	
	if(!list_add(service->servers, server)) {
		server_free(server);
		printf("Can'nt add server\n");
		return false;
	}

	NetworkInterface* ni = ni_get(ni_num);
	Map* servers = ni_config_get(ni, "pn.lb.servers");
	if(servers == NULL) {
		printf("Can'nt found servers\n");
		return false;
	}
	if(!map_put(servers, (void*)((uint64_t)protocol << 48 | (uint64_t)server_addr << 16 | (uint64_t)server_port), server)) {
		printf("map put fail\n");
	}

	return true;
}

static Server* find_server(Service* service, uint32_t addr, uint16_t port) {
	List* servers = service->servers;

	ListIterator iter;
	list_iterator_init(&iter, servers);

	while(list_iterator_has_next(&iter)) {
		Server* server = list_iterator_next(&iter);
		if((server->addr == addr) && (server->port == port)) {
			return server;
		}
	}

	return NULL;
}

void server_is_remove_grace(Server* server) {
	if(server->state == LB_SERVER_STATE_OK)
		return;

	if(map_is_empty(server->sessions)) { //none session
		if(server->event_id != 0)
			event_timer_remove(server->event_id);

		//remove from ni
		Map* servers = ni_config_get(server->ni, "pn.lb.servers");
		map_remove(servers, (void*)((uint64_t)server->protocol << 48 | (uint64_t)server->addr << 16 | (uint64_t)server->port));

		//remove from service
		List* _servers = server->service->servers;
		list_remove_data(_servers, server);

		server_free(server);
	}
}

bool server_remove(uint8_t protocol, uint32_t service_addr, uint16_t service_port, uint8_t service_ni_num, uint32_t server_addr, uint16_t server_port, uint8_t ni_num, uint64_t wait) {
	bool server_delete_event(void* context) {
		Server* server = context;
		Service* service = server->service;

		Map* sessions = server->sessions;
		if(map_is_empty(sessions)) {
			list_remove_data(service->servers, server);
			server_free(server);
			return false;
		} else {
			//Delete all sessions
			MapIterator iter;
			map_iterator_init(&iter, sessions);
			while(map_iterator_has_next(&iter)) {
				MapEntry* entry = map_iterator_remove(&iter);
				Session* session = entry->data;
				map_remove(session->server->sessions, (void*)((uint64_t)session->protocol << 48 | (uint64_t)session->s_addr << 16 | (uint64_t)session->s_port));


				session_free(session);
			}

			list_remove_data(service->servers, server);
			server_free(server);
		}

		return false;
	}

	Service* service = find_service(ni_get(service_ni_num), protocol, service_addr, service_port);
	if(service == NULL) {
		printf("Can'nt found service\n");
		return false;
	}

	Server* server = find_server(service, server_addr, server_port);
	if(server == NULL) {
		printf("Can'nt found server\n");
		return false;
	}

	if(map_is_empty(server->sessions)) {
		list_remove_data(service->servers, server);
		server_free(server);
		return true;
	} else {
		server->state = LB_SERVER_STATE_REMOVING;
		server->event_id = event_timer_add(server_delete_event, server, wait, 0);

		return true;
	}
}

bool server_remove_force(uint8_t protocol, uint32_t service_addr, uint16_t service_port, uint8_t service_ni_num, uint32_t server_addr, uint16_t server_port, uint8_t server_ni_num) {
	NetworkInterface* ni = ni_get(service_ni_num);
	Service* service = find_service(ni, protocol, service_addr, service_port);
	if(service == NULL)
		return false;

	return true;
}

void server_dump(uint8_t protocol, uint32_t service_addr, uint16_t service_port, uint8_t service_ni_num) {
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

	NetworkInterface* ni = ni_get(service_ni_num);
	if(ni == NULL) {
		printf("Can'nt found Network Interface\n");
		return;
	}

	Service* service = find_service(ni, protocol, service_addr, service_port);
	if(service == NULL) {
		printf("Can'nt found service\n");
		return;
	}

	ListIterator iter;
	list_iterator_init(&iter, service->servers);

	printf("State\t\tAddr:Port\t\tMode\tNIC\tSessions\n");
	while(list_iterator_has_next(&iter)) {
		Server* server = list_iterator_next(&iter);
		print_state(server->state);
		print_addr_port(server->addr, server->port);
		print_mode(server->mode);
		print_ni_num(server->ni_num);
		print_session_count(server->sessions);
		printf("\n");
	}
}

