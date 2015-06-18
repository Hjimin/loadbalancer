#ifndef __SERVER_H__
#define __SERVER_H__
#include <stdbool.h>
#include <net/ni.h>
#include <util/map.h>

#include "service.h"

#define LB_SERVER_STATE_OK		1
#define LB_SERVER_STATE_REMOVING	2

#define LB_MODE_NAT	1
#define LB_MODE_DNAT	2
#define LB_MODE_DR	3

typedef struct {
	Service*	service;
	uint8_t		state;
	uint64_t	event_id;
	uint8_t		protocol;
	uint32_t	addr;
	uint16_t	port;
	uint8_t		mode;
	NetworkInterface* ni;
	uint8_t		ni_num;
	Map*		sessions;
} Server;

bool service_arp_process(Packet* packet);
Server* server_alloc(Service* service);
bool server_free(Server* server);
bool server_add(uint8_t protocol, uint32_t service_addr, uint16_t service_port, uint8_t service_ni_num, uint32_t server_addr, uint16_t server_port, uint8_t mode, uint8_t out_port);
bool server_is_empty(NetworkInterface* ni);
bool server_remove(uint8_t protocol, uint32_t service_addr, uint16_t service_port, uint8_t service_ni_num, uint32_t server_addr, uint16_t server_port, uint8_t ni_num, uint64_t wait);
bool server_remove_force(uint8_t protocol, uint32_t service_addr, uint16_t service_port, uint8_t service_ni_num, uint32_t server_addr, uint16_t server_port, uint8_t server_ni_num);
void server_is_remove_grace(Server* server);
void server_dump(uint8_t protocol, uint32_t service_addr, uint16_t service_port, uint8_t service_ni_num);

#endif/* __SERVER_H__*/
