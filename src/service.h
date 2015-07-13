#ifndef __SERVICE_H__
#define __SERVICE_H__

#include <net/ni.h>
#include <util/list.h>
#include <util/map.h>

#include "session.h"
#include "interface.h"
#include "server.h"

#define LB_SERVICE_STATE_OK		1
#define LB_SERVICE_STATE_REMOVING	2

#define LB_SERVICE_DEFAULT_TIMEOUT	30000000

#define PN_LB_SERVICE	"pn.lb.service"

typedef struct Service{
	Interface*	service_interface;
	uint8_t		state;
	uint8_t		schedule;
	uint32_t	robin;
	uint64_t	timeout;
	uint64_t	event_id;

	Map*		private_interfaces;
	List*		enable_servers;
	List*		disable_servers;

	void*		(*get_server)(struct Service*, void* context);
} Service;

Service* service_alloc(Interface* public_interface, Interface** private_interface, uint8_t private_interface_count, uint8_t schedule);
bool service_add(NetworkInterface* ni, Service* service);
bool service_is_empty(NetworkInterface* ni);
Service* service_get(NetworkInterface* ni);

Session* service_alloc_session(NetworkInterface* ni, uint8_t protocol, uint32_t saddr, uint16_t sport, uint32_t daddr, uint16_t dport);
Session* service_get_session(NetworkInterface* ni, uint8_t protocol, uint32_t saddr, uint16_t sport);

void service_is_remove_grace(Service* service);
bool service_remove(Service* service, uint64_t wait);
bool service_remove_force(Service* service);
void service_dump();
#endif /*__SERVICE_H__*/
