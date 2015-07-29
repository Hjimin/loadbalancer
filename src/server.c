#include <stdio.h>
#include <string.h>
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

#include "server.h"
#include "service.h"
#include "session.h"
#include "nat.h"
#include "dnat.h"
#include "dr.h"

extern void* __gmalloc_pool;

static bool server_add(NetworkInterface* ni, Server* server) {
	Map* servers = ni_config_get(ni, SERVERS);
	if(!servers) {
		servers = map_create(16, NULL, NULL, ni->pool);
		if(!servers)
			return false;
		if(!ni_config_put(ni, SERVERS, servers)) {
			map_destroy(servers);
			return false;
		}
	}

	uint64_t key = (uint64_t)server->endpoint.protocol << 48 | (uint64_t)server->endpoint.addr << 16 | (uint64_t)server->endpoint.port;
	if(!map_put(servers, (void*)key, server)) {
		printf("Server map put fail\n");
		goto map_put_error;
	}

	//Add to service active & deactive server list
	uint32_t count = ni_count();
	for(int i = 0; i < count; i++) {
		NetworkInterface* service_ni = ni_get(i);
		Map* services = ni_config_get(service_ni, SERVICES);
		if(!services)
			continue;

		MapIterator iter;
		map_iterator_init(&iter, services);
		while(map_iterator_has_next(&iter)) {
			MapEntry* entry = map_iterator_next(&iter);
			Service* service = entry->data;

			if(!service->private_endpoints)
				continue;

			if(!map_contains(service->private_endpoints, ni))
				continue;

			if(server->state == SERVER_STATE_ACTIVE) {
				if(!list_add(service->active_servers, server)) {
					printf("List add fail\n");
					goto list_add_error;
				}
			} else {
				if(!list_add(service->deactive_servers, server)) {
					printf("List add fail\n");
					goto list_add_error;
				}
			}
		}
	}

	return true;

list_add_error:
	//remove to service's server list
	for(int i = 0; i < count; i++) {
		NetworkInterface* service_ni = ni_get(i);
		Map* services = ni_config_get(service_ni, SERVICES);
		if(!services)
			continue;

		MapIterator iter;
		map_iterator_init(&iter, services);
		while(map_iterator_has_next(&iter)) {
			MapEntry* entry = map_iterator_next(&iter);
			Service* service = entry->data;

			if(!service->private_endpoints)
				continue;

			if(!map_contains(service->private_endpoints, ni))
				continue;

			if(!list_remove_data(service->active_servers, server))
				continue;
			else if(!list_remove_data(service->deactive_servers, server))
				continue;
		}
	}

map_put_error:
	if(map_is_empty(servers)) {
		ni_config_remove(ni, SERVERS);
		map_destroy(servers);
	}

	return false;
}

Server* server_alloc(Endpoint* server_endpoint) {
	size_t size = sizeof(Server);
	Server* server = (Server*)__malloc(size, server_endpoint->ni->pool);
	if(!server) {
		printf("Can'nt allocation server\n");
		return NULL;
	}
	bzero(server, size);

	memcpy(&server->endpoint, server_endpoint, sizeof(Endpoint));

	server->state = SERVER_STATE_ACTIVE;
	server->event_id = 0;
	server_set_mode(server, MODE_NAT);

	if(!server_add(server->endpoint.ni, server))
		goto server_add_fail;

	return server;

server_add_fail:
	__free(server, server_endpoint->ni->pool);

	return NULL;
}

bool server_set_mode(Server* server, uint8_t mode) {
	switch(mode) {
		case MODE_NAT:
			switch(server->endpoint.protocol) {
				case IP_PROTOCOL_TCP:
					server->create = nat_tcp_session_alloc;
					break;
				case IP_PROTOCOL_UDP:
					server->create = nat_udp_session_alloc;
					break;
			}
			break;
		case MODE_DNAT:
			switch(server->endpoint.protocol) {
				case IP_PROTOCOL_TCP:
					server->create = dnat_tcp_session_alloc;
					break;
				case IP_PROTOCOL_UDP:
					server->create = dnat_udp_session_alloc;
					break;
			}
			break;
		case MODE_DR:
			server->create = dr_session_alloc;
			break;
		default:
			return false;
	}

	server->mode = mode;

	return true;
}

bool server_set_weight(Server* server, uint8_t weight) {
	server->weight = weight;

	return true;
}

bool server_free(Server* server) {
	uint32_t count = ni_count();
	for(int i = 0; i < count; i++) {
		NetworkInterface* service_ni = ni_get(i);
		Map* services = ni_config_get(service_ni, SERVICES);

		if(!services)
			continue;

		MapIterator iter;
		map_iterator_init(&iter, services);
		while(map_iterator_has_next(&iter)) {
			MapEntry* entry = map_iterator_next(&iter);
			Service* service = entry->data;

			if(!service->private_endpoints)
				continue;

			if(map_contains(service->private_endpoints, server->endpoint.ni)) {
				if(list_remove_data(service->active_servers, server))
					continue;
				else if(list_remove_data(service->deactive_servers, server))
					continue;
			}
		}
	}

	__free(server, server->endpoint.ni->pool);

	return true;
}

Server* server_get(Endpoint* server_endpoint) {
	Map* servers = ni_config_get(server_endpoint->ni, SERVERS);
	if(!servers)
		return NULL;

	uint64_t key = (uint64_t)server_endpoint->protocol << 48 | (uint64_t)server_endpoint->addr << 16 | (uint64_t)server_endpoint->port;
	Server* server = map_get(servers, (void*)key);

	return server;
}

Session* server_get_session(Endpoint* client_endpoint) {
	Map* sessions = ni_config_get(client_endpoint->ni, SESSIONS);
	if(!sessions)
		return NULL;

	uint64_t key = ((uint64_t)client_endpoint->protocol << 48 | (uint64_t)client_endpoint->addr << 16 | (uint64_t)client_endpoint->port);
	Session* session = map_get(sessions, (void*)key);

	return session;
}

bool server_remove(Server* server, uint64_t wait) {
	bool server_delete_event(void* context) {
		Server* server = context;

		server_remove_force(server);

		return false;
	}
	bool server_delete0_event(void* context) {
		Server* server = context;

		if(map_is_empty(server->sessions)) {
			server_remove_force(server);

			return false;
		}

		return true;
	}
	if(!server)
		return false;

	if(!server->sessions || (server->sessions && map_is_empty(server->sessions))) {
		return server_remove_force(server);
	} else {
		server->state = SERVER_STATE_DEACTIVE;

		uint32_t count = ni_count();
		for(int i = 0; i < count; i++) {
			NetworkInterface* service_ni = ni_get(i);
			Map* services = ni_config_get(service_ni, SERVICES);
			if(!services)
				continue;

			MapIterator iter;
			map_iterator_init(&iter, services);
			while(map_iterator_has_next(&iter)) {
				MapEntry* entry = map_iterator_next(&iter);
				Service* service = entry->data;
				if(list_remove_data(service->active_servers, server))
					list_add(service->deactive_servers, server);
			}
		}

		if(wait)
			server->event_id = event_timer_add(server_delete_event, server, wait, 0);
		else
			server->event_id = event_timer_add(server_delete0_event, server, 1000000, 1000000);

		return true;
	}
}

bool server_remove_force(Server* server) {
	if(server->event_id != 0) {
		event_timer_remove(server->event_id);
		server->event_id = 0;
	}

	Map* sessions = ni_config_get(server->endpoint.ni, SESSIONS);
	if(sessions && !map_is_empty(sessions)) {
		MapIterator iter;
		map_iterator_init(&iter, sessions);
		while(map_iterator_has_next(&iter)) {
			MapEntry* entry = map_iterator_next(&iter);
			Session* session = entry->data;
			
			event_timer_remove(session->event_id);
			service_free_session(session);
		}
	}

	server->state = SERVER_STATE_DEACTIVE;
	//delet from ni
	Map* servers = ni_config_get(server->endpoint.ni, SERVERS);
	uint64_t key = (uint64_t)server->endpoint.protocol << 48 | (uint64_t)server->endpoint.addr << 16 | (uint64_t)server->endpoint.port;
	map_remove(servers, (void*)key);

	server_free(server);

	if(map_is_empty(servers)) {
		ni_config_remove(server->endpoint.ni, SERVERS);
		map_destroy(servers);
	}

	return true;
}

void server_dump() {
	void print_state(uint8_t state) {
		if(state == SERVER_STATE_ACTIVE)
			printf("ACTIVE\t\t");
		else if(state == SERVER_STATE_DEACTIVE)
			printf("DEACTIVE\t");
		else
			printf("Unknown\t");
	}
	void print_mode(uint8_t mode) {
		if(mode == MODE_NAT)
			printf("NAT\t");
		else if(mode == MODE_DNAT)
			printf("DNAT\t");
		else if(mode == MODE_DR)
			printf("DR\t");
		else
			printf("Unknown\t");
	}
	void print_addr_port(uint32_t addr, uint16_t port) {
		printf("%d.%d.%d.%d:%d\t", (addr >> 24) & 0xff, (addr >> 16) & 0xff,
				(addr >> 8) & 0xff, addr & 0xff, port);
	}
	void print_ni_num(NetworkInterface* ni) {
		uint8_t count = ni_count();
		for(int i = 0; i < count; i++) {
			if(ni == ni_get(i))
				printf("%d\t", i);
		}
	}
	void print_weight(uint8_t weight) {
		printf("%d\t", weight);
	}
	void print_session_count(Map* sessions) {
		if(sessions)
			printf("%d\t", map_size(sessions));
		else
			printf("0\t");
	}

	printf("State\t\tAddr:Port\t\tMode\tNIC\tWeight\tSessions\n");
	uint8_t count = ni_count();
	for(int i = 0; i < count; i++) {
		Map* servers = ni_config_get(ni_get(i), SERVERS);
		if(!servers)
			continue;

		MapIterator iter;
		map_iterator_init(&iter, servers);
		while(map_iterator_has_next(&iter)) {
			MapEntry* entry = map_iterator_next(&iter);
			Server* server = entry->data;

			print_state(server->state);
			print_addr_port(server->endpoint.addr, server->endpoint.port);
			print_mode(server->mode);
			print_ni_num(server->endpoint.ni);
			print_weight(server->weight);
			print_session_count(server->sessions);
			printf("\n");
		}
	}
}
