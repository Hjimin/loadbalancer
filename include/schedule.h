#ifndef __SCHEDULE_H__
#define __SCHEDULE_H__

#include "server.h"
#include "service.h"

#define SCHEDULE_ROUND_ROBIN		1
#define SCHEDULE_RANDOM			2
#define SCHEDULE_LEAST			3
#define SCHEDULE_SOURCE_IP_HASH		4
#define SCHEDULE_WEIGHTED_ROUND_ROBIN	5

typedef struct _RoundRobin {
	uint32_t robin;
} RoundRobin;

Server* schedule_round_robin(Service* service, Endpoint* client_endpoint);
Server* schedule_weighted_round_robin(Service* service, Endpoint* client_endpoint);
Server* schedule_random(Service* service, Endpoint* client_endpoint);
Server* schedule_least(Service* service, Endpoint* client_endpoint);
Server* schedule_source_ip_hash(Service* service, Endpoint* client_endpoint);

#endif /*__SCHEDULE_H__*/
