#ifndef __SCHEDULE_H__
#define __SCHEDULE_H__

#include "service.h"

#define LB_SCHEDULE_ROUND_ROBIN			1
#define LB_SCHEDULE_RANDOM			2
#define LB_SCHEDULE_LEAST			3
#define LB_SCHEDULE_SOURCE_IP_HASH		4
#define LB_SCHEDULE_WEIGHTED_ROUND_ROBIN	5

void* schedule_round_robin(Service* service, void* _client_interface);
void* schedule_weighted_round_robin(Service* service, void* _client_interface);
void* schedule_random(Service* service, void* _client_interface);
void* schedule_least(Service* service, void* _client_interface);
void* schedule_source_ip_hash(Service* service, void* _client_interface);

#endif /*__SCHEDULE_H__*/
