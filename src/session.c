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

bool session_recharge(Session* session) {
	bool session_free_event(void* context) {
		Session* session = context;
		session->event_id = 0;
		session_free(session);

		return false;
	}
	if(session->fin)
		return true;

	if(!session->event_id) {
		session->event_id = event_timer_add(session_free_event, session, 30000000, 30000000);
		if(session->event_id)
			return true;
		else
			return false;
	} else
		return event_timer_update(session->event_id);
}

bool session_free(Session* session) {
	if(session->event_id != 0) {
		event_timer_remove(session->event_id);
		session->event_id = 0;
	}

	//Remove from Service Interface NI
	Map* sessions = ni_config_get(session->service_interface->ni, PN_LB_SESSIONS);
	uint64_t client_key = session_get_client_key(session);
	if(!map_remove(sessions, (void*)client_key)) {
		printf("Can'nt remove session from servers\n");
		goto error_session_free1;
	}

	//Remove from Server NI
	sessions = ni_config_get(session->server_interface->ni, PN_LB_SESSIONS);
	uint64_t private_key = session_get_private_key(session);
	if(!map_remove(sessions, (void*)private_key)) {
		printf("Can'nt remove session from private ni\n");
		goto error_session_free2;
	}

	//Remove from Server
	if(!map_remove(session->server_interface->sessions, (void*)private_key)) {
		printf("Can'nt remove session from servers\n");
		goto error_session_free3;
	}

	session->session_free(session);

	return true;

error_session_free3:
error_session_free2:
error_session_free1:

	return false;
}

bool session_set_fin(Session* session) {
	bool gc(void* context) {
		Session* session = context;
		session->event_id = 0;
		
		printf("Timeout fin\n");
		session_free(session);
		
		return false;
	}
		
	if(session->event_id)
		event_timer_remove(session->event_id);

	session->fin = true;
	session->event_id = event_timer_add(gc, session, 3000, 3000);
	if(session->event_id == 0) {
		printf("Can'nt add service\n");
		return false;
	}
	
	return true;
}

inline uint64_t session_get_private_key(Session* session) {
	return (uint64_t)session->private_interface->protocol << 48 | (uint64_t)session->private_interface->addr << 16 | (uint64_t)session->private_interface->port;
}

inline uint64_t session_get_client_key(Session* session) {
	return (uint64_t)session->client_interface->protocol << 48 | (uint64_t)session->client_interface->addr << 16 | (uint64_t)session->client_interface->port;
}
