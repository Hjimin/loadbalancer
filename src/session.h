#ifndef __SESSION_H__
#define __SESSION_H__

#include <net/ni.h>

#include "interface.h"

#define SESSION_IN	1
#define SESSION_OUT	2

#define PN_LB_SESSIONS	"pn.lb.sessions"

typedef struct Session{
	Interface*	client_interface;
	Interface*	service_interface;
	Interface*	private_interface;
	Interface*	server_interface;

	uint64_t	event_id;
	bool		fin;

	bool(*loadbalancer_pack)(struct Session* session, Packet* packet);
	bool(*loadbalancer_unpack)(struct Session* session, Packet* packet);
	bool(*session_free)(struct Session* session);
} Session;

bool session_recharge(Session* session);
bool session_free(Session* session);
bool session_set_fin(Session* session);
uint64_t session_get_private_key(Session* session);
uint64_t session_get_client_key(Session* session);

#endif /*__SESSION_H__*/
