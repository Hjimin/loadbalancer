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

#include "addr_manager.h"
#include "service.h"
#include "server.h"
#include "session.h"
#include "schedule.h"
#include "loadbalancer.h"

extern void* __gmalloc_pool;

Service* service_alloc(Endpoint* service_endpoint) {
	bool service_add(int ni_num, Service* service) {
//		Map* services = nic_config_get(ni, SERVICES);
		Map* services = lb_get_services(ni_num);
/*
		if(!services) {
			services = map_create(16, NULL, NULL, ni->pool);
			if(!services)
				return false;
			if(!nic_config_put(ni, SERVICES, services))
				return false;
		}
*/
		uint64_t key = (uint64_t)service->endpoint.protocol << 48 | (uint64_t)service->endpoint.addr << 16 | (uint64_t)service->endpoint.port;

		if(!map_put(services, (void*)key, service)) {
			if(map_is_empty(services)) {
				nic_config_remove(nic_get(ni_num), SERVICES);
				map_destroy(services);
			}

			return false;
		} 

		return true;
	}

	//add ip
	if(!addr_alloc(service_endpoint->ni, service_endpoint->addr)) { 
		printf("Can'nt allocate address\n");
		return NULL;
	}

	//port alloc
	if(service_endpoint->protocol == IP_PROTOCOL_TCP) {
		if(!tcp_port_alloc0(service_endpoint->ni, service_endpoint->addr, service_endpoint->port)) {
			printf("Can'nt allocate port\n");
			goto port_alloc_fail;
		}
	} else if(service_endpoint->protocol == IP_PROTOCOL_UDP) {
		if(!udp_port_alloc0(service_endpoint->ni, service_endpoint->addr, service_endpoint->port)) {
			printf("Can'nt allocate port\n");
			goto port_alloc_fail;
		}
	}

	//service alloc
	Service* service = __malloc(sizeof(Service), service_endpoint->ni->pool);
	if(!service) {
		printf("Can'nt allocate Service\n");
		goto service_alloc_fail;
	}

	bzero(service, sizeof(Service));
	memcpy(&service->endpoint, service_endpoint, sizeof(Endpoint));

	service->timeout = SERVICE_DEFAULT_TIMEOUT;
	service->state = SERVICE_STATE_ACTIVE;

	service_set_schedule(service, SCHEDULE_ROUND_ROBIN);

	//add to service list
	if(!service_add(service_endpoint->ni_num, service)) {
		printf("Can'nt add SErvice\n");
		goto service_add_fail;
	}

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
	addr_free(service_endpoint->ni, service_endpoint->addr);

	return false;
}

bool service_free(Service* service) {
	bool service_remove(int ni_num, Service* service) {
//		Map* services = nic_config_get(ni, SERVICES);
		Map* services = lb_get_services(ni_num);
		if(!services) {
			return false;
		}

		uint64_t key = (uint64_t)service->endpoint.protocol << 48 | (uint64_t)service->endpoint.addr << 16 | (uint64_t)service->endpoint.port;

		return map_remove(services, (void*)(uintptr_t)key);
	}

	//remove from service list
	service_remove(service->endpoint.ni_num, service);

	//remove private endpoirnts
	if(service->private_endpoints) {
		MapIterator iter;
		map_iterator_init(&iter, service->private_endpoints);

		while(map_iterator_has_next(&iter)) {
			MapEntry* entry = map_iterator_next(&iter);
			NIC* ni = entry->key;
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
	addr_free(service->endpoint.ni, service->endpoint.addr);

	//service free
	__free(service, service->endpoint.ni->pool);

	return true;
}

bool service_set_schedule(Service* service, uint8_t schedule) {
	switch(schedule) {
		case SCHEDULE_ROUND_ROBIN:
			service->next = schedule_round_robin;
			RoundRobin* rr = __malloc(sizeof(RoundRobin), service->endpoint.ni->pool);
			if(!rr) {
				printf("Can'nt set Round Robin\n");
				return false;
			}
			__free(service->priv, service->endpoint.ni->pool);
			service->priv = rr;
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
		case SCHEDULE_DESTINATION_IP_HASH:
			service->next = schedule_destination_ip_hash;
			break;
		case SCHEDULE_WEIGHTED_ROUND_ROBIN:
			service->next = schedule_weighted_round_robin;
			RoundRobin* wrr = __malloc(sizeof(RoundRobin), service->endpoint.ni->pool);
			if(!wrr) {
				printf("Can'nt set Round Robin\n");
				return false;
			}
			__free(service->priv, service->endpoint.ni->pool);
			service->priv = wrr;
			break;
		default:
			return false;
	}
	service->schedule = schedule;

	return true;
}

bool service_add_private_addr(Service* service, Endpoint* _private_endpoint) {
	if(!addr_alloc(_private_endpoint->ni, _private_endpoint->addr)) {
		printf("Can'nt allocate addr\n");
		return false;
	}

	if(!service->private_endpoints) {
		service->private_endpoints = map_create(16, NULL, NULL, service->endpoint.ni->pool);
		if(!service->private_endpoints) {
			goto private_endpoints_create_fail;
		}
	}

	ssize_t size = sizeof(Endpoint);
	Endpoint* private_endpoint = __malloc(size, _private_endpoint->ni->pool);
	memcpy(private_endpoint, _private_endpoint, size);

	if(!map_put(service->private_endpoints, private_endpoint->ni, private_endpoint)) {
		goto private_endpoint_put_fail;
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

//	Map* servers = nic_config_get(private_endpoint->ni, SERVERS);
	Map* servers = lb_get_servers(private_endpoint->ni_num);

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

	return true;

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
	map_remove(service->private_endpoints, private_endpoint->ni);

private_endpoint_put_fail:
	if(map_is_empty(service->private_endpoints)) {
		map_destroy(service->private_endpoints);
		service->private_endpoints = NULL;
	}

private_endpoints_create_fail:
	//private_free(private);
	addr_free(_private_endpoint->ni, _private_endpoint->addr);

	return false;
}

bool service_set_private_addr(Service* service, Endpoint* private_endpoint) {
	return false;
}

bool service_remove_private_addr(Service* service, NIC* ni) {
	if(!service->private_endpoints)
		return false;

	//Remove Address in NIC
	Endpoint* private_endpoint = map_get(service->private_endpoints, ni);
	if(!private_endpoint)
		return false;

	if(map_is_empty(service->private_endpoints)) {
		map_destroy(service->private_endpoints);
		service->private_endpoints = NULL;
	}

	//Remove servers belong NIC
	Map* servers = nic_config_get(ni, SERVERS);
//	Map* servers = lb_get_servers(ni_num);
	
	if(servers) {
		MapIterator iter;
		map_iterator_init(&iter, servers);
		while(map_iterator_has_next(&iter)) {
			MapEntry* entry = map_iterator_next(&iter);
			Server* server = entry->data;

			if(server->state == SERVER_STATE_ACTIVE) {
				list_remove_data(service->active_servers, server);
			} else {
				list_remove_data(service->deactive_servers, server);
			}
		}
	}

	addr_free(private_endpoint->ni, private_endpoint->addr);
	__free(private_endpoint, private_endpoint->ni->pool);

	return true;
}

Session* service_get_session(Endpoint* client_endpoint) {
//	Map* sessions = nic_config_get(client_endpoint->ni, SESSIONS);
	Map* sessions = lb_get_sessions(client_endpoint->ni_num);
	if(!sessions)
		return NULL;

	Session* session = map_get(sessions, (void*)((uint64_t)client_endpoint->protocol << 48 | (uint64_t)client_endpoint->addr << 16 | (uint64_t)client_endpoint->port));

	return session;
}


Session* service_alloc_session(Endpoint* service_endpoint, Endpoint* client_endpoint) {
	Service* service = service_get(service_endpoint);
	if(!service)
		return NULL;

	if(service->state != SERVICE_STATE_ACTIVE)
		return NULL;

	Server* server = service->next(service, client_endpoint);
	if(!server)
		return NULL;

	Endpoint* private_endpoint = map_get(service->private_endpoints, server->endpoint.ni);
	Session* session = server->create(&(server->endpoint), &(service->endpoint), client_endpoint, private_endpoint);
	if(!session)
		return NULL;

	//Add to Service
	uint64_t public_key = session_get_public_key(session);
	if(!service->sessions) {
		service->sessions = map_create(4096, NULL, NULL, service->endpoint.ni->pool);
		if(!service->sessions)
			goto service_map_put_fail;
	}
	if(!map_put(service->sessions, (void*)public_key, session))
		goto service_map_put_fail;

	//Add to Service Interface NI
//	Map* sessions = nic_config_get(service->endpoint.ni, SESSIONS);
	Map* sessions = lb_get_sessions(service->endpoint.ni_num);
	
	if(!sessions) {
		sessions = map_create(4096, NULL, NULL, service->endpoint.ni->pool);
		if(!sessions)
			goto service_nic_map_put_fail;

		if(!nic_config_put(service->endpoint.ni, SESSIONS, sessions)) {
			map_destroy(sessions);
			goto service_nic_map_put_fail;
		}
	}
	if(!map_put(sessions, (void*)public_key, session))
		goto service_nic_map_put_fail;

	//Add to Server
	uint64_t private_key = session_get_private_key(session);
	//uint64_t private_key = ((uint64_t)client_endpoint->protocol << 48 | (uint64_t)client_endpoint->addr << 16 | (uint64_t)client_endpoint->port); 
	if(!server->sessions) {
		server->sessions = map_create(4096, NULL, NULL, server->endpoint.ni->pool);
		if(!server->sessions)
			goto server_map_put_fail;
	}
	if(!map_put(server->sessions, (void*)private_key, session))
		goto server_map_put_fail;

	//Add to Server Interface NI
//	sessions = nic_config_get(server->endpoint.ni, SESSIONS);
	sessions = lb_get_sessions(server->endpoint.ni_num);

	if(!sessions) {
		sessions = map_create(4096, NULL, NULL, server->endpoint.ni->pool);
		if(!sessions)
			goto server_nic_map_put_fail;

		if(!nic_config_put(server->endpoint.ni, SESSIONS, sessions)) {
			map_destroy(sessions);
			goto server_nic_map_put_fail;
		}
	}
	if(!map_put(sessions, (void*)private_key, session))
		goto server_nic_map_put_fail;

	session->fin = false;

	return session;

server_nic_map_put_fail:
	map_remove(server->sessions, (void*)private_key);
server_map_put_fail:
//	sessions = nic_config_get(service->endpoint.ni, SESSIONS);
	sessions = lb_get_sessions(service->endpoint.ni_num);
	
	map_remove(sessions, (void*)public_key);
service_nic_map_put_fail:
	map_remove(service->sessions, (void*)public_key);
service_map_put_fail:
	session->free(session);

	return NULL;
}

bool service_free_session(Session* session) {
	//Remove from Server NI
//	Map* sessions = nic_config_get(session->server_endpoint->ni, SESSIONS);
	Map* sessions = lb_get_sessions(session->server_endpoint->ni_num);
	uint64_t private_key = session_get_private_key(session);
	if(!map_remove(sessions, (void*)private_key)) {
		printf("Can'nt remove session from private ni\n");
		goto session_free_fail;
	}

	Server* server = server_get(session->server_endpoint);
	//Remove from Server
	if(!map_remove(server->sessions, (void*)private_key)) {
		printf("Can'nt remove session from private\n");
		goto session_free_fail;
	}

	//Remove from Service Interface NI
//	sessions = nic_config_get(session->public_endpoint->ni, SESSIONS);
	sessions = lb_get_sessions(session->public_endpoint->ni_num);
	uint64_t client_key = session_get_public_key(session);
	if(!map_remove(sessions, (void*)client_key)) {
		printf("Can'nt remove session from service ni\n");
		goto session_free_fail;
	}

	//Remove from Service 
	Service* service = service_get(session->public_endpoint);
	if(!map_remove(service->sessions, (void*)client_key)) {
		printf("Can'nt remove session from service ni\n");
		goto session_free_fail;
	}

	session->free(session);

	return true;

session_free_fail:

	return false;
}

bool service_empty(int ni_num) {
//	Map* services = nic_config_get(ni, SERVICES);
	Map* services = lb_get_services(ni_num);

	return map_is_empty(services);
}

Service* service_get(Endpoint* service_endpoint) {
//	Map* services = nic_config_get(service_endpoint->ni, SERVICES);
	Map* services = lb_get_services(service_endpoint->ni_num);

	if(!services) {
		return NULL;
	}

	uint64_t key = (uint64_t)service_endpoint->protocol << 48 | (uint64_t)service_endpoint->addr << 16 | (uint64_t)service_endpoint->port;

	return map_get(services, (void*)key);
}

bool service_remove(Service* service, uint64_t wait) {
	bool service_delete_event(void* context) {
		Service* service = context;

		service->event_id = 0;
		service_remove_force(service);

		return false;
	}
	bool service_delete0_event(void* context) {
		Service* service = context;

		if(map_is_empty(service->sessions)) { //none session
			service->event_id = 0;
			service_remove_force(service);

			return false;
		}

		return true;
	}

	if(!service->sessions || (service->sessions && map_is_empty(service->sessions))) { //none session
		return service_remove_force(service); 
	} else {
		service->state = SERVICE_STATE_DEACTIVE;

		if(wait)
			service->event_id = event_timer_add(service_delete_event, service, wait, 0);
		else {
			service->event_id = event_timer_add(service_delete0_event, service, 2000000, 2000000);
		}

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

	//Remove sessions
//	Map* sessions = nic_config_get(service->endpoint.ni, SESSIONS);
	Map* sessions = lb_get_sessions(service->endpoint.ni_num);
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
				printf("Round-Robin\t\t");
				break;
			case SCHEDULE_RANDOM:
				printf("Random\t\t\t");
				break;
			case SCHEDULE_LEAST:
				printf("Least Connection\t");
				break;
			case SCHEDULE_SOURCE_IP_HASH:
				printf("Source Hashing\t\t");
				break;
			case SCHEDULE_DESTINATION_IP_HASH:
				printf("Destination Hashing\t");
				break;
			case SCHEDULE_WEIGHTED_ROUND_ROBIN:
				printf("W Round-Robin\t");
				break;
		}
	}
	void print_nic_num(NIC* ni) {
		uint8_t count = nic_count();
		for(int i = 0; i < count; i++) {
			if(ni == nic_get(i))
				printf("%d\t", i);
		}
	}
	void print_private_addr_port(uint32_t addr) {
		printf("%d.%d.%d.%d\t\t", (addr >> 24) & 0xff, (addr >> 16) & 0xff,
				(addr >> 8) & 0xff, addr & 0xff);
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


	printf("State\t\tProtocol\tAddr:Port\t\tPrivate_Addr:Port\tSchedule\t\tNIC\tSession\tServer\n");
	int count = nic_count();
	for(int i = 0; i < count; i++) {
//		NIC* ni = nic_get(i);

//		Map* services = nic_config_get(ni, SERVICES);
		Map* services = lb_get_services(i);
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

			MapIterator pr_iter;
			Map* private_endpoints = service->private_endpoints;
			if(!private_endpoints) {
				print_private_addr_port(0);
			} else { 
				map_iterator_init(&pr_iter, private_endpoints);
				while(map_iterator_has_next(&pr_iter)) {
					MapEntry* entry = map_iterator_next(&pr_iter);
					Endpoint* pr_end = entry->data;
					print_private_addr_port(pr_end->addr);
				}

			}
			print_schedule(service->schedule);
			print_nic_num(service->endpoint.ni);
			//Map* sessions = ni_config_get(service->endpoint.ni, SESSIONS);
			print_session_count(service->sessions);
			print_server_count(service->active_servers);
			printf(" / ");
			print_server_count(service->deactive_servers);
			printf("\n");
		}
	}
}
