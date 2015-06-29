#ifndef __SERVER_H__
#define __SERVER_H__
#include <stdbool.h>
#include <net/ni.h>
#include <util/map.h>

#include "interface.h"

#define LB_SERVER_STATE_OK		1
#define LB_SERVER_STATE_REMOVING	2

#define LB_MODE_NAT	1
#define LB_MODE_DNAT	2
#define LB_MODE_DR	3

#define PN_LB_SERVERS	"pn.lb.servers"

typedef struct{
	Interface*	server_interface;

	uint8_t		state;
	uint8_t		mode;
	uint64_t	event_id;

	Map*		sessions;
}Server;

bool server_arp_process(Packet* packet);
uint64_t server_arp_get_mac(NetworkInterface* ni, uint32_t saddr, uint32_t daddr);
bool server_icmp_process(Packet* packet);
Server* server_alloc(Interface* server_interface, uint8_t mode);
bool server_free(Server* server);
Server* server_get(NetworkInterface* ni, uint8_t protocol, uint32_t addr, uint16_t port);
bool server_add(NetworkInterface* ni, Server* server);

bool server_remove(Server* server, uint64_t wait);
bool server_remove_force(Server* server);
void server_is_remove_grace(Server* server);

void server_dump();

#endif/* __SERVER_H__*/
