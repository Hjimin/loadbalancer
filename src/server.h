#ifndef __SERVER_H__
#define __SERVER_H__ #include <stdbool.h>
#include <net/ni.h>
#include <util/map.h>

#include "service.h"

#define LB_SERVER_STATE_OK		1
#define LB_SERVER_STATE_REMOVING	2

#define LB_MODE_NAT	1
#define LB_MODE_DNAT	2
#define LB_MODE_DR	3

typedef struct {
	uint8_t		state;
	uint64_t	event_id;
	uint8_t		protocol;
	uint32_t	addr;
	uint16_t	port;
	uint8_t		mode;

	NetworkInterface* ni;
	uint8_t		ni_in;
	List*		ni_out_list;

	Map*		sessions;
} Server;

Server* server_alloc(Service* service);
bool server_free(Server* server);
bool server_add(uint8_t protocol, uint32_t server_addr, uint16_t server_port, uint8_t mode, uint8_t out_port);
bool server_is_empty(NetworkInterface* ni);
Server* server_found(uint8_t protocol, uint32_t server_addr, uint16_t server_port, uint8_t ni_num);

bool server_remove(Server* server, uint64_t wait);
bool server_remove_force(Server* server);
void server_is_remove_grace(Server* server);

void server_dump();

#endif/* __SERVER_H__*/
