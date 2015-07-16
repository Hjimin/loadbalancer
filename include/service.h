#ifndef __SERVICE_H__
#define __SERVICE_H__

#include <net/ni.h>
#include <util/list.h>
#include <util/map.h>

#include "session.h"
#include "endpoint.h"
#include "server.h"

#define SERVICE_STATE_ACTIVE	1
#define SERVICE_STATE_DEACTIVE	2

#define SERVICE_DEFAULT_TIMEOUT	30000000

#define SERVICES	"net.lb.services"

typedef struct _Service {
	Endpoint	endpoint;

	uint64_t	timeout;
	uint8_t		state;
	uint64_t	event_id;

	Map*		private_endpoints;
	List*		active_servers;
	List*		deactive_servers;
	
	Set*		sessions;

	uint8_t		schedule;
	Server*		(*next)(struct _Service*, uint32_t public_addr);
	void*		priv;
} Service;


Service* service_alloc(NetworkInterface* ni, uint8_t protocol, uint32_t addr, uint16_t port);
bool service_set_schedule(Service* service, uint8_t schedule);

bool service_add_private_addr(Service* service, NetworkInterface* ni, uint32_t addr);
bool service_set_private_addr(Service* service, NetworkInterface* ni, uint32_t addr);
bool service_remove_private_addr(Service* service, NetworkInterface* ni);

bool service_free(Service* service);

Service* service_get(NetworkInterface* ni, uint8_t protocol, uint32_t addr, uint16_t port);
bool service_empty(NetworkInterface* ni);

Session* service_alloc_session(NetworkInterface* ni, uint8_t protocol, uint32_t saddr, uint16_t sport, uint32_t daddr, uint16_t dport);
Session* service_get_session(NetworkInterface* ni, uint8_t protocol, uint32_t saddr, uint16_t sport);
bool service_free_session(Session* session);

void service_is_remove_grace(Service* service);
bool service_remove(Service* service, uint64_t wait);
bool service_remove_force(Service* service);
void service_dump();

#endif /*__SERVICE_H__*/
