#include "schedule.h"
#include "server.h"
#include "service.h"
#include "endpoint.h"

Server* schedule_round_robin(Service* service, Endpoint* client_endpoint) {
	uint32_t count = list_size(service->active_servers);
	RoundRobin* roundrobin = service->priv;
	if(count == 0)
		return NULL; 

	uint32_t index = (roundrobin->robin++) % count;

	return list_get(service->active_servers, index);
}

Server* schedule_weighted_round_robin(Service* service, Endpoint* client_endpoint) {
	uint32_t count = list_size(service->active_servers);
	RoundRobin* roundrobin = service->priv;
	if(count == 0)
		return NULL; 

	uint32_t whole_weight = 0;
	ListIterator iter;
	list_iterator_init(&iter, service->active_servers);
	while(list_iterator_has_next(&iter)) {
		Server* server = list_iterator_next(&iter);
		whole_weight += server->weight;
	}

	uint32_t _index = (roundrobin->robin++) & whole_weight;
	list_iterator_init(&iter, service->active_servers);
	while(list_iterator_has_next(&iter)) {
		Server* server = list_iterator_next(&iter);
		if(_index < server->weight)
			return server;
		else
			_index -= server->weight;
	}

	return NULL;
}

Server* schedule_random(Service* service, Endpoint* client_endpoint) {
	inline uint64_t cpu_tsc() {
		uint64_t time;
		uint32_t* p = (uint32_t*)&time;
		asm volatile("rdtsc" : "=a"(p[0]), "=d"(p[1]));
		
		return time;
	}

	uint32_t count = list_size(service->active_servers);
	if(count == 0)
		return NULL;

	uint32_t random_num = cpu_tsc() % count;

	return list_get(service->active_servers, random_num);
}

Server* schedule_least(Service* service, Endpoint* client_endpoint) {
	uint32_t count = list_size(service->active_servers);
	if(count == 0)
		return NULL; 

	List* servers = service->active_servers;
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

Server* schedule_source_ip_hash(Service* service, Endpoint* client_endpoint) {
	uint32_t count = list_size(service->active_servers);
	if(count == 0)
		return NULL;

	uint32_t index = client_endpoint->addr % count;

	return list_get(service->active_servers, index);
}

Server* schedule_min_request_time(Service* service, Endpoint* client_endpoint) {
	return NULL;
}
