#ifndef __SCHEDULE_H__
#define __SCHEDULE_H__

#include "schedule.h"
#include "server.h"
#include "interface.h"

void* schedule_round_robin(Service* service, void* _client_interface) {
	uint32_t count = list_size(service->enable_servers);
	if(count == 0)
		return NULL; 

	uint32_t index = (service->robin++) % count;

	return list_get(service->enable_servers, index);
}

void* schedule_weighted_round_robin(Service* service, void* _client_interface) {
	uint32_t count = list_size(service->enable_servers);
	if(count == 0)
		return NULL; 

	uint32_t whole_weight = 0;
	ListIterator iter;
	list_iterator_init(&iter, service->enable_servers);
	while(list_iterator_has_next(&iter)) {
		Server* server = list_iterator_next(&iter);
		whole_weight += server->weight;
	}

	uint32_t _index = (service->robin++) & whole_weight;
	list_iterator_init(&iter, service->enable_servers);
	while(list_iterator_has_next(&iter)) {
		Server* server = list_iterator_next(&iter);
		if(_index < server->weight)
			return server;
		else
			_index -= server->weight;
	}

	return NULL;
}

void* schedule_random(Service* service, void* _client_interface) {
	inline uint64_t cpu_tsc() {
		uint64_t time;
		uint32_t* p = (uint32_t*)&time;
		asm volatile("rdtsc" : "=a"(p[0]), "=d"(p[1]));
		
		return time;
	}

	uint32_t count = list_size(service->enable_servers);
	if(count == 0)
		return NULL;

	uint32_t random_num = cpu_tsc() % count;

	return list_get(service->enable_servers, random_num);
}

void* schedule_least(Service* service, void* _client_interface) {
	uint32_t count = list_size(service->enable_servers);
	if(count == 0)
		return NULL; 

	List* servers = service->enable_servers;
	ListIterator iter;
	list_iterator_init(&iter, servers);
	Server* server = NULL;
	uint32_t session_count = UINT32_MAX;
	while(list_iterator_has_next(&iter)) {
		Server* _server = list_iterator_next(&iter);

		if(map_size(_server->sessions) < session_count)
			server = _server;
	}

	return server;
}

void* schedule_source_ip_hash(Service* service, void* _client_interface) {
	Interface* client_interface = _client_interface;
	uint32_t count = list_size(service->enable_servers);
	if(count == 0)
		return NULL;

	uint32_t index = client_interface->addr % count;

	return list_get(service->enable_servers, index);
}
#endif /*__SCHEDULE_H__*/
