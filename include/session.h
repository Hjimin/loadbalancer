#ifndef __SESSION_H__
#define __SESSION_H__

#include <net/ni.h>

#include "endpoint.h"

#define SESSION_IN	1
#define SESSION_OUT	2

#define SESSIONS	"net.lb.sessions"

typedef struct _Session {
	Endpoint*	server_endpoint;
	Endpoint*	public_endpoint;
	Endpoint	client_endpoint;
	Endpoint	private_endpoint;

	uint64_t	event_id;
	bool		fin;
	
	bool(*translate)(struct _Session* session, Packet* packet);
	bool(*untranslate)(struct _Session* session, Packet* packet);
	bool(*free)(struct _Session* session);
} Session;

bool session_recharge(Session* session); //move in untranslate & translate
//bool session_free(Session* session);
bool session_set_fin(Session* session); //move in untranslate
uint64_t session_get_private_key(Session* session);
uint64_t session_get_public_key(Session* session);

#endif /*__SESSION_H__*/
