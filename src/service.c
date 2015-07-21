#include <stdio.h>
#include <string.h>
#define DONT_MAKE_WRAPPER
#include <_malloc.h>
#undef DONT_MAKE_WRAPPER
#include <util/event.h>
#include <util/set.h>
#include <net/interface.h>
#include <net/checksum.h>
#include <net/ether.h>
#include <net/ip.h>
#include <net/arp.h>
#include <net/icmp.h>
#include <net/tcp.h>
#include <net/udp.h>

#include "service.h"
#include "server.h"
#include "session.h"
#include "schedule.h"

extern void* __gmalloc_pool;

Service* service_alloc(Endpoint* service_endpoint) {
	bool service_add(NetworkInterface* ni, Service* service) {
		Map* services = ni_config_get(ni, SERVICES);
		if(!services) {
			services = map_create(16, NULL, NULL, ni->pool);
			if(!services)
				return false;
			if(!ni_config_put(ni, SERVICES, services))
				return false;
		}

		uint64_t key = (uint64_t)service->endpoint.protocol << 48 | (uint64_t)service->endpoint.addr << 16 | (uint64_t)service->endpoint.port;

		return map_put(services, (void*)key, service);
	}
	//add ip
	if(!ni_ip_get(service_endpoint->ni, service_endpoint->addr)) { 
		if(!ni_ip_add(service_endpoint->ni, service_endpoint->addr))
			return NULL;
	}

	//port alloc
	if(service_endpoint->protocol == IP_PROTOCOL_TCP) {
		if(!tcp_port_alloc0(service_endpoint->ni, service_endpoint->addr, service_endpoint->port))
			goto port_alloc_fail;
	} else if(service_endpoint->protocol == IP_PROTOCOL_UDP) {
		if(!udp_port_alloc0(service_endpoint->ni, service_endpoint->addr, service_endpoint->port))
			goto port_alloc_fail;
	} else
		return NULL;

	//service alloc
	Service* service = __malloc(sizeof(Service), service_endpoint->ni->pool);
	if(!service)
		goto service_alloc_fail;

	bzero(service, sizeof(Service));
	memcpy(&service->endpoint, service_endpoint, sizeof(Endpoint));

	service->timeout = SERVICE_DEFAULT_TIMEOUT;
	service->state = SERVICE_STATE_ACTIVE;

	service_set_schedule(service, SCHEDULE_ROUND_ROBIN);

	//add to service list
	if(!service_add(service_endpoint->ni, service))
		goto service_add_fail;

	return service;

service_add_fail:
service_alloc_fail:
	//port free
	if(service_endpoint->protocol == IP_PROTOCOL_TCP) {
		tcp_port_free(service_endpoint->ni, service_endpoint->addr, service_endpoint->port);
	} else if(service_endpoint->protocol == IP_PROTOCOL_UDP) {
		udp_port_free(service_endpoint->ni, service_endpoint->addr, service_endpoint->port);
	}

port_alloc_fail:
	//delete if port is empty
	;
	IPv4Interface* interface = ni_ip_get(service_endpoint->ni, service_endpoint->addr);
	if(set_is_empty(interface->tcp_ports) && set_is_empty(interface->udp_ports)) {
		ni_ip_remove(service_endpoint->ni, service_endpoint->addr);
	}

	return false;
}

bool service_free(Service* service) {
	bool service_remove(NetworkInterface* ni, Service* service) {
		Map* services = ni_config_get(ni, SERVICES);
		if(!services) {
			return false;
		}

		uint64_t key = (uint64_t)service->endpoint.protocol << 48 | (uint64_t)service->endpoint.addr << 16 | (uint64_t)service->endpoint.port;

		return map_remove(services, (void*)(uintptr_t)key);
	}

	//remove from service list
	service_remove(service->endpoint.ni, service);

	//remove private endpoirnts
	if(service->private_endpoints) {
		MapIterator iter;
		map_iterator_init(&iter, service->private_endpoints);

		while(map_iterator_has_next(&iter)) {
			MapEntry* entry = map_iterator_next(&iter);
			NetworkInterface* ni = entry->key;
			//uint32_t addr = (uint32_t)(uintptr_t)entry->data;
			service_remove_private_addr(service, ni);
		}

		map_destroy(service->private_endpoints);
	}
	//server list free
	if(service->active_servers)
		list_destroy(service->active_servers);
	if(service->deactive_servers)
		list_destroy(service->deactive_servers);

	//port free
	if(service->endpoint.protocol == IP_PROTOCOL_TCP) {
		tcp_port_free(service->endpoint.ni, service->endpoint.addr, service->endpoint.port);
	} else if(service->endpoint.protocol == IP_PROTOCOL_UDP) {
		udp_port_free(service->endpoint.ni, service->endpoint.addr, service->endpoint.port);
	}

	//delete ip if port is empty
	IPv4Interface* interface = ni_ip_get(service->endpoint.ni, service->endpoint.addr);
	if(set_is_empty(interface->tcp_ports) && set_is_empty(interface->udp_ports)) {
		ni_ip_remove(service->endpoint.ni, service->endpoint.addr);
	}

	//service free
	__free(service, service->endpoint.ni->pool);

	return true;
}

bool service_set_schedule(Service* service, uint8_t schedule) {
	switch(schedule) {
		case SCHEDULE_ROUND_ROBIN:
			service->next = schedule_round_robin;
			break;
		case SCHEDULE_RANDOM:
			service->next = schedule_random;
			break;
		case SCHEDULE_LEAST:
			service->next = schedule_least;
			break;
		case SCHEDULE_SOURCE_IP_HASH:
			service->next = schedule_source_ip_hash;
			break;
		case SCHEDULE_WEIGHTED_ROUND_ROBIN:
			service->next = schedule_weighted_round_robin;
			break;
		default:
			return false;
	}
	service->schedule = schedule;

	return true;
}

bool service_add_private_addr(Service* service, Endpoint* _private_endpoint) {
	if(!service->private_endpoints) {
		service->private_endpoints = map_create(16, NULL, NULL, service->endpoint.ni->pool);
		if(!service->private_endpoints)
			return false;
	}

	ssize_t size = sizeof(Endpoint);
	Endpoint* private_endpoint = __malloc(size, service->endpoint.ni->pool);
	memcpy(private_endpoint, _private_endpoint, size);

	if(!ni_ip_get(private_endpoint->ni, private_endpoint->addr)) {
		if(!ni_ip_add(private_endpoint->ni, private_endpoint->addr)) {
			map_remove(service->private_endpoints, private_endpoint->ni);
			__free(private_endpoint, service->endpoint.ni->pool);
			return false;
		}
	}

	//create active & deactive server list
	if(!service->active_servers) {
		service->active_servers = list_create(service->endpoint.ni->pool);
		if(!service->active_servers)
			goto list_create_fail;

		service->deactive_servers = list_create(service->endpoint.ni->pool);
		if(!service->deactive_servers) {
			list_destroy(service->active_servers);
			service->active_servers = NULL;

			goto list_create_fail;
		}
	}

	Map* servers = ni_config_get(private_endpoint->ni, SERVERS);

	if(servers) {
		MapIterator iter;
		map_iterator_init(&iter, servers);

		while(map_iterator_has_next(&iter)) {
			MapEntry* entry = map_iterator_next(&iter);
			Server* server = entry->data;

			if(server->state == SERVER_STATE_ACTIVE) {
				if(!list_add(service->active_servers, server))
					goto server_add_fail;
			} else {
				if(!list_add(service->deactive_servers, server))
					goto server_add_fail;
			}
		}
	}

	if(!map_put(service->private_endpoints, private_endpoint->ni, private_endpoint)) {
		goto private_endpoint_put_fail;
	}

	return true;

private_endpoint_put_fail:
	service_remove_private_addr(service, private_endpoint->ni);

server_add_fail:
	;
	MapIterator iter;
	map_iterator_init(&iter, servers);

	while(map_iterator_has_next(&iter)) {
		MapEntry* entry = map_iterator_next(&iter);
		Server* server = entry->data;

		if(server->state == SERVER_STATE_ACTIVE) {
			list_remove_data(service->active_servers, server);
			continue;
		} else {
			list_remove_data(service->deactive_servers, server);
			continue;
		}
	}

list_create_fail:

	return false;
}

bool service_set_private_addr(Service* service, Endpoint* private_endpoint) {
	return false;
}

bool service_remove_private_addr(Service* service, NetworkInterface* ni) {
	if(!service->private_endpoints)
		return false;

	//Remove servers belong NetworkInterface
	List* servers = ni_config_get(ni, SERVERS);
	ListIterator iter;
	list_iterator_init(&iter, servers);
	while(list_iterator_has_next(&iter)) {
		Server* server = list_iterator_next(&iter);

		if(server->state == SERVER_STATE_ACTIVE) {
			list_remove_data(service->active_servers, server);
		} else {
			list_remove_data(service->deactive_servers, server);
		}
	}

	//Remove Address in NetworkInterface
	Endpoint* private_endpoint = map_remove(service->private_endpoints, ni);
	if(!private_endpoint)
		return false;
	uint32_t addr = private_endpoint->addr;
	__free(private_endpoint, service->endpoint.ni->pool);

	uint16_t count = ni_count();
	for(int i = 0; i < count; i++) {
		NetworkInterface* ni = ni_get(i);
		Map* Services = ni_config_get(ni, SERVICES);

		MapIterator iter;
		map_iterator_init(&iter, Services);

		while(map_iterator_has_next(&iter)) {
			MapEntry* entry = map_iterator_next(&iter);
			Service* _service = entry->data;
			if(service == _service)
				continue;

			if(!_service->private_endpoints)
				continue;

			Endpoint* _private_endpoint = map_get(_service->private_endpoints, ni);

			if(addr == _private_endpoint->addr)
				return true;
		}
	}
	
	ni_ip_remove(ni, addr);

	return true;
}

Session* service_get_session(Endpoint* client_endpoint) {
	Map* sessions = ni_config_get(client_endpoint->ni, SESSIONS);
	if(!sessions)
		return NULL;

	Session* session = map_get(sessions, (void*)((uint64_t)client_endpoint->protocol << 48 | (uint64_t)client_endpoint->addr << 16 | (uint64_t)client_endpoint->port));

	return session;
}


Session* service_alloc_session(Endpoint* service_endpoint, Endpoint* client_endpoint) {
	Service* service = service_get(service_endpoint);
	if(!service)
		return NULL;

	if(!service->sessions) {
		service->sessions = map_create(4096, NULL, NULL, service->endpoint.ni->pool);
		if(!service->sessions)
			return NULL;
	}

	if(!((client_endpoint->addr == service->endpoint.addr) && (client_endpoint->protocol == service->endpoint.protocol) && (client_endpoint->port == service->endpoint.port)))
		return NULL;

	if(service->state != SERVICE_STATE_ACTIVE)
		return NULL;

	Server* server = service->next(service, client_endpoint);
	if(!server)
		return NULL;

	if(!service->private_endpoints)
		return NULL;

	Endpoint* private_endpoint = map_get(service->private_endpoints, server->endpoint.ni);
	Session* session = server->create(&(server->endpoint), &(service->endpoint), client_endpoint, private_endpoint);
	if(!session)
		goto error_get_session;

	//Add to Service
	uint64_t public_key = session_get_public_key(session);
	if(!service->sessions) {
		service->sessions = map_create(4096, NULL, NULL, service->endpoint.ni->pool);
		if(!service->sessions)
			goto service_map_createa_fail;
	}
	if(!map_put(service->sessions, (void*)public_key, session))
		goto error_session_map_put1;

	//Add to Service Interface NI
	Map* sessions = ni_config_get(service->endpoint.ni, SESSIONS);
	if(!map_put(sessions, (void*)public_key, session))
		goto error_session_map_put1;

	uint64_t private_key = session_get_private_key(session);
	//Add to Server
	if(!server->sessions) {
		server->sessions = map_create(4096, NULL, NULL, server->endpoint.ni->pool);
		if(!server->sessions)
			goto server_map_createa_fail;
	}
	if(!map_put(server->sessions, (void*)private_key, session))
		goto error_session_map_put2;

	//Add to Server Interface NI
	sessions = ni_config_get(server->endpoint.ni, SESSIONS);
	if(!map_put(sessions, (void*)private_key, session))
		goto error_session_map_put2;



	session->fin = false;
	session->event_id = 0;
	session_recharge(session);

	return session;

	map_remove(sessions, (void*)private_key);

error_session_map_put2:
	sessions = ni_config_get(service->endpoint.ni, SESSIONS);
	map_remove(sessions, (void*)public_key);

server_map_createa_fail:

error_session_map_put1:
	session->free(session);

service_map_createa_fail:

error_get_session:
error_get_server:

	return NULL;
}

bool service_free_session(Session* session) {
	//Remove from Service Interface NI
	Map* sessions = ni_config_get(session->public_endpoint->ni, SESSIONS);
	uint64_t client_key = session_get_public_key(session);
	if(!map_remove(sessions, (void*)client_key)) {
		printf("Can'nt remove session from servers\n");
		goto session_free_fail;
	}

	//Remove from Server NI
	sessions = ni_config_get(session->server_endpoint->ni, SESSIONS);
	uint64_t private_key = session_get_private_key(session);
	if(!map_remove(sessions, (void*)private_key)) {
		printf("Can'nt remove session from private ni\n");
		goto session_free_fail;
	}

	Server* server = server_get(session->server_endpoint);
	//Remove from Server
	if(!map_remove(server->sessions, (void*)private_key)) {
		printf("Can'nt remove session from servers\n");
		goto session_free_fail;
	}

	if(session->event_id != 0) {
		event_timer_remove(session->event_id);
		session->event_id = 0;
	}

	session->free(session);

	return true;

session_free_fail:
	return false;
}

bool service_empty(NetworkInterface* ni) {
	Map* services = ni_config_get(ni, SERVICES);

	return map_is_empty(services);
}

Service* service_get(Endpoint* service_endpoint) {
	Map* services = ni_config_get(service_endpoint->ni, SERVICES);
	if(!services)
		return NULL;

	uint64_t key = (uint64_t)service_endpoint->protocol << 48 | (uint64_t)service_endpoint->addr << 16 | (uint64_t)service_endpoint->port;

	return map_get(services, (void*)key);
}

void service_is_remove_grace(Service* service) {
	if(service->state == SERVICE_STATE_ACTIVE)
		return;

	Map* sessions = ni_config_get(service->endpoint.ni, SESSIONS);
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
		Map* sessions = ni_config_get(service->endpoint.ni, SESSIONS);
		if(map_is_empty(sessions)) { //none session
			service_remove_force(service);

			return true;
		}

		return false;
	}

	Map* sessions = ni_config_get(service->endpoint.ni, SESSIONS);
	if(map_is_empty(sessions)) { //none session
		service_remove_force(service); 
		return true;
	} else {
		service->state = SERVICE_STATE_DEACTIVE;

		if(wait)
			service->event_id = event_timer_add(service_delete_event, service, wait, 0);
		else
			service->event_id = event_timer_add(service_delete0_event, service, 1000000, 1000000);

		return true;
	}

	return true;
}

bool service_remove_force(Service* service) {
	if(service->event_id != 0) {
		event_timer_remove(service->event_id);
		service->event_id = 0;
	}

	service->state = SERVICE_STATE_DEACTIVE;

	Map* sessions = ni_config_get(service->endpoint.ni, SESSIONS);
	if(!map_is_empty(sessions)) {
	}

	Map* private_endpoints = service->private_endpoints;
	MapIterator iter;
	map_iterator_init(&iter, private_endpoints);
	while(map_iterator_has_next(&iter)) {
		MapEntry* entry = map_iterator_next(&iter);
		//uint32_t addr = entry->data;
		NetworkInterface* ni = entry->key;
		service_remove_private_addr(service, ni);
	}

	service_free(service);

	return true;
}

void service_dump() {
	void print_state(uint8_t state) {
		if(state == SERVICE_STATE_ACTIVE)
			printf("ACTIVE\t\t");
		else if(state == SERVICE_STATE_DEACTIVE)
			printf("DEACTIVE\t");
		else
			printf("Unknown\t");
	}
	void print_protocol(uint8_t protocol) {
		if(protocol == IP_PROTOCOL_TCP)
			printf("TCP\t\t");
		else if(protocol == IP_PROTOCOL_UDP)
			printf("UDP\t\t");
		else
			printf("Unknown\t");
	}
	void print_addr_port(uint32_t addr, uint16_t port) {
		printf("%d.%d.%d.%d:%d\t", (addr >> 24) & 0xff, (addr >> 16) & 0xff,
				(addr >> 8) & 0xff, addr & 0xff, port);
	}
	void print_schedule(uint8_t schedule) {
		switch(schedule) {
			case SCHEDULE_ROUND_ROBIN:
				printf("Round-Robin\t");
				break;
			case SCHEDULE_RANDOM:
				printf("Random\t\t");
				break;
			case SCHEDULE_LEAST:
				printf("Least\t\t");
				break;
			case SCHEDULE_SOURCE_IP_HASH:
				printf("Hash\t\t");
				break;
			case SCHEDULE_WEIGHTED_ROUND_ROBIN:
				printf("Weight Round-Robin\t\t");
				break;
			default:
				printf("Unnowkn\t");
				break;
		}
	}
	void print_ni_num(NetworkInterface* ni) {
		uint8_t count = ni_count();
		for(int i = 0; i < count; i++) {
			if(ni == ni_get(i))
				printf("%d\t", i);
		}
	}
	void print_session_count(Map* sessions) {
		if(sessions)
			printf("%d\t", map_size(sessions));
		else
			printf("0\t");
	}
	void print_server_count(List* servers) {
		if(servers)
			printf("%d", list_size(servers));
		else
			printf("0");
	}


	printf("State\t\tProtocol\tAddr:Port\t\tSchedule\tNIC\tSession\tServer\n");
	int count = ni_count();
	for(int i = 0; i < count; i++) {
		NetworkInterface* ni = ni_get(i);

		Map* services = ni_config_get(ni, SERVICES);
		if(!services)
			continue;

		MapIterator iter;
		map_iterator_init(&iter, services);
			
		while(map_iterator_has_next(&iter)) {
			MapEntry* entry = map_iterator_next(&iter);
			Service* service = entry->data;

			print_state(service->state);
			print_protocol(service->endpoint.protocol);
			print_addr_port(service->endpoint.addr, service->endpoint.port);
			print_schedule(service->schedule);
			print_ni_num(service->endpoint.ni);
			Map* sessions = ni_config_get(service->endpoint.ni, SESSIONS);
			print_session_count(sessions);
			print_server_count(service->active_servers);
			printf(" \040 ");
			print_server_count(service->deactive_servers);
			printf("\n");
		}
	}
}
