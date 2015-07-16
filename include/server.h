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
	Set*		sessions;
	
	Session*	(*create)(Endpoint* server_endpoint, Endpoint* service_endpoint, uint32_t public_addr, uint16_t public_port, uint32_t private_addr);
	uint8_t		priv[0];
} Server;

Server* server_alloc(NetworkInterface* ni, uint8_t protocol, uint32_t addr, uint16_t port);
bool server_free(Server* server);
bool server_set_mode(Server* server, uint8_t mode);

Server* server_get(NetworkInterface* ni, uint8_t protocol, uint32_t addr, uint16_t port);

Session* server_get_session(NetworkInterface* ni, uint8_t protocol, uint32_t daddr, uint16_t dport);

bool server_remove(Server* server, uint64_t wait);
bool server_remove_force(Server* server);
void server_is_remove_grace(Server* server);

void server_dump();

#endif/* __SERVER_H__*/
