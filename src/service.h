#ifndef __SERVICE_H__
#define __SERVICE_H__
#include <net/ni.h>
#include "server.h"
#include "interface.h"

#define LB_SERVICE_STATE_OK		1
#define LB_SERVICE_STATE_REMOVING	2

#define LB_SCHEDULE_ROUND_ROBIN		1
#define LB_SCHEDULE_RANDOM		2

#define LB_SERVICE_DEFAULT_TIMEOUT	30000000

#define SERVICE_ALLOCATE_FAIL		-10000
#define SERVICE_LIST_CREATE_FAIL	-10001

typedef struct Service{
	Interface*	service_interface;
	uint8_t		state;
	uint8_t		schedule;
	uint32_t	robin;
	uint64_t	timeout;
	uint64_t	event_id;

	List*		server_nis;
	List*		servers;

	Server* 	(*get_server)(struct Service*);
} Service;

Service* service_alloc(Interface* public_interface, uint8_t* out_port, uint8_t out_port_count, uint8_t schedule);
bool service_add(NetworkInterface* ni, Service* service);
bool service_is_empty(NetworkInterface* ni);
Service* service_get(NetworkInterface* ni);

void service_is_remove_grace(Service* service);
bool service_remove(Service* service, uint64_t wait);
bool service_remove_force(Service* service);
void service_dump();
#endif
