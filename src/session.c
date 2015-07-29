#include <stdio.h>
#include <malloc.h>
#include <gmalloc.h>
#include <util/map.h>
#include <util/event.h>
#include <net/ether.h>
#include <net/arp.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>

#include "session.h"
#include "service.h"

bool session_recharge(Session* session) {
	bool session_free_event(void* context) {
		Session* session = context;
		service_free_session(session);

		return false;
	}
	if(session->fin)
		return true;

	if(!session->event_id) {
		session->event_id = event_timer_add(session_free_event, session, 300000000, 300000000);
		if(!session->event_id) {
			printf("Can'nt add service event\n");
			return false;
		}

		return true;
	} else {
		if(!event_timer_update(session->event_id)) {
			session->event_id = 0;
			return false;
		}
			
		return true;
	}
}

bool session_set_fin(Session* session) {
	bool gc(void* context) {
		Session* session = context;
		service_free_session(session);
		
		return false;
	}
	if(session->fin)
		return true;
		
	if(session->event_id) {
		event_timer_remove(session->event_id);
	}

	session->fin = true;
	session->event_id = event_timer_add(gc, session, 3000, 3000);
	if(session->event_id == 0) {
		printf("Can'nt add service event\n");
		return false;
	}
	
	return true;
}

inline uint64_t session_get_private_key(Session* session) {
	return (uint64_t)session->private_endpoint.protocol << 48 | (uint64_t)session->private_endpoint.addr << 16 | (uint64_t)session->private_endpoint.port;
}

inline uint64_t session_get_public_key(Session* session) {
	return (uint64_t)session->client_endpoint.protocol << 48 | (uint64_t)session->client_endpoint.addr << 16 | (uint64_t)session->client_endpoint.port;
}
