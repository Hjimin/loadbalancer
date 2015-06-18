#include <stdio.h>
#include <malloc.h>
#include <util/map.h>
#include <util/event.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>

#include "service.h"
#include "server.h"
#include "session.h"

void session_recharge(Session* session) {
	bool session_free_event(void* context) {
		Session* session = context;
		session_free(session);

		return false;
	}
	if(session->fin)
		return;

	if(session->event_id != 0)
		event_timer_remove(session->event_id);

	session->event_id = event_timer_add(session_free_event, session, session->service->timeout, session->service->timeout);
}

Session* session_alloc(NetworkInterface* ni, uint8_t protocol, uint32_t saddr, uint16_t sport, uint32_t daddr, uint16_t dport) {
	Service* service = find_service(ni, protocol, daddr, dport);
	if(service == NULL) {
		return NULL;
	}

	if(service->state != LB_SERVICE_STATE_OK)
		return NULL;
	
	Session* session = malloc(sizeof(Session));
	if(session == NULL) {
		printf("Can'nt allocate Session\n");
		return NULL;
	}

	session->protocol = protocol;
	session->s_addr = saddr;
	session->s_port = sport;
	session->v_addr = saddr;
	session->v_port = sport;

	session->service = service;
	Server* server = server_alloc(service);
	if(server == NULL) {
		printf("Can'nt create session\n");
		free(session);
		return NULL;
	}
	session->server = server; 

	if(session->server->mode == LB_MODE_NAT) {
		session->v_addr = (uint32_t)(uint64_t)ni_config_get(server->ni, "ip");
		if(protocol == IP_PROTOCOL_TCP)
			session->v_port = tcp_port_alloc(server->ni);
		else if(protocol == IP_PROTOCOL_UDP)
			session->v_port = udp_port_alloc(server->ni);
	}

	session->event_id = 0;
	session->fin = false;
	if(!map_put(server->sessions, (void*)((uint64_t)session->protocol << 48 | (uint64_t)session->v_addr << 16 | (uint64_t)session->v_port), session)) {
		printf("map_put fail\n");
	}
	if(!map_put(service->sessions, (void*)((uint64_t)session->protocol << 48 | (uint64_t)session->s_addr << 16 | (uint64_t)session->s_port), session)) {
		printf("map_put fail\n");
	}
	session_recharge(session);
	
	return session;
}

Session* session_get(NetworkInterface* ni, uint8_t protocol, uint32_t saddr, uint16_t sport, uint32_t daddr, uint16_t dport) {
	Service* service = find_service(ni, protocol, daddr, dport);
	if(service == NULL)
		return NULL;

	Session* session = map_get(service->sessions, (void*)((uint64_t)protocol << 48 | (uint64_t)saddr << 16 | (uint64_t)sport));

	if(session != NULL)
		session_recharge(session);

	return session;
}

bool session_free(Session* session) {
	if(!map_remove(session->server->sessions, (void*)((uint64_t)session->protocol << 48 | (uint64_t)session->v_addr << 16 | (uint64_t)session->v_port)))
		printf("Can'nt remove session from servers\n");
	if(!map_remove(session->service->sessions, (void*)((uint64_t)session->protocol << 48 | (uint64_t)session->s_addr << 16 | (uint64_t)session->s_port)))
		printf("Can'nt remove session from services\n");

	server_is_remove_grace(session->server);
	service_is_remove_grace(session->service);
	if(session->server->mode == LB_MODE_NAT) {
		if(session-> protocol == IP_PROTOCOL_TCP)
			tcp_port_free(session->server->ni, session->v_port);
		else if(session-> protocol == IP_PROTOCOL_UDP)
			udp_port_free(session->server->ni, session->v_port);
	}

	free(session);

	return true;
}

Session* session_get_nat(NetworkInterface* ni, uint8_t protocol, uint32_t saddr, uint16_t sport, uint32_t daddr, uint16_t dport) {
	Map* servers = ni_config_get(ni, "pn.lb.servers");
	if(servers == NULL)
		return NULL;

	Server* server = map_get(servers, (void*)((uint64_t)protocol << 48 | (uint64_t)saddr << 16 | (uint64_t)sport));
	if(server == NULL) {
		printf("fail\n");
		return NULL;
	}
	
	Session* session = map_get(server->sessions, (void*)((uint64_t)protocol << 48 | (uint64_t)daddr << 16 | (uint64_t)dport));

	if(session != NULL) {
		session_recharge(session);
	}

	return session;
}

Session* session_get_dnat(NetworkInterface* ni, uint8_t protocol, uint32_t saddr, uint16_t sport, uint32_t daddr, uint16_t dport) {
	Map* servers = ni_config_get(ni, "pn.lb.servers");
	if(servers == NULL)
		return NULL;

	Server* server = map_get(servers, (void*)((uint64_t)protocol << 48 | (uint64_t)saddr << 16 | (uint64_t)sport));
	if(server == NULL)
		return NULL;
	
	Session* session = map_get(server->service->sessions, (void*)((uint64_t)protocol << 48 | (uint64_t)daddr << 16 | (uint64_t)dport));

	if(session != NULL)
		session_recharge(session);

	return session;
}

bool session_set_fin(Session* session) {
	bool gc(void* context) {
		Session* session = context;
		
		printf("Timeout fin\n");
		session_free(session);
		
		return false;
	}
		
	if(session->event_id)
		event_timer_remove(session->event_id);
	session->event_id = event_timer_add(gc, session, 3000, 3000);
	if(session->event_id == 0) {
		printf("Can'nt add service\n");
		return false;
	}
	session->fin = true;
	
	return true;
}
