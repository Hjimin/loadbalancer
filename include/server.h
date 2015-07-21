#ifndef __SERVER_H__
#define __SERVER_H__
#include <stdbool.h>
#include <net/ni.h>
#include <util/map.h>
#include <util/set.h>

#include "session.h"
#include "endpoint.h"

#define SERVER_STATE_ACTIVE	1
#define SERVER_STATE_DEACTIVE	2

#define MODE_NAT	1
#define MODE_DNAT	2
#define MODE_DR		3

#define SERVERS	"net.lb.servers"

typedef struct _Server {
	Endpoint	endpoint;

	uint8_t		state;
	uint64_t	event_id;
	uint8_t		mode;
	uint8_t		weight;
	Map*		sessions;
	
	Session*	(*create)(Endpoint* server_endpoint, Endpoint* service_endpoint, Endpoint* client_endpoint, Endpoint* private_endpoint);
	void*		priv;
} Server;

Server* server_alloc(Endpoint* server_endpoint);
bool server_free(Server* server);
bool server_set_mode(Server* server, uint8_t mode);

Server* server_get(Endpoint* server_endpoint);

Session* server_get_session(Endpoint* client_endpoint);

bool server_remove(Server* server, uint64_t wait);
bool server_remove_force(Server* server);
void server_is_remove_grace(Server* server);

void server_dump();

#endif/* __SERVER_H__*/
