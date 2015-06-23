#include <net/ni.h>

#include "service.h"
#include "server.h"

#define SESSION_IN	1
#define SESSION_OUT	2

typedef struct Session{
	Interface*	client_interface;
	Service*	service;
	Interface*	private_interface;
	Server*		server;

	uint64_t	event_id;
	bool		fin;

	bool(*loadbalancer_pack)(struct Session* session, Packet* packet, uint8_t direct);
	bool(*session_free)(struct Session* session);
} Session;

Session* session_alloc(NetworkInterface* ni, uint8_t protocol, uint32_t saddr, uint16_t sport, uint32_t daddr, uint16_t dport);
Session* session_get(NetworkInterface* ni, uint8_t protocol, uint32_t saddr, uint16_t sport, uint32_t daddr, uint16_t dport);
bool session_free(Session* session);
Session* session_get_from_service(NetworkInterface* ni, uint8_t protocol, uint32_t saddr, uint16_t sport);
Session* session_get_from_server(NetworkInterface* ni, uint8_t protocol, uint32_t daddr, uint16_t dport);
bool session_set_fin(Session* session);
