#ifndef __SERVICE_H__
#define __SERVICE_H__
#include <net/ni.h>
#include "interface.h"

#define LB_SERVICE_STATE_OK		1
#define LB_SERVICE_STATE_REMOVING	2

#define LB_SCHEDULE_ROUND_ROBIN 1

typedef struct {
	uint8_t		state;
	uint8_t		schedule;
	uint32_t	robin;
	Interface*	public_interface;
	List*		private_interfaces;
	uint64_t	timeout;
	uint64_t	event_id;
} Service;

bool service_arp_process(Packet* packet);
bool service_add(uint8_t protocol, uint32_t addr, uint16_t port, uint8_t schedule, uint8_t ni_in, uint8_t* ni_out, uint8_t ni_out_count);
bool service_is_empty(NetworkInterface* ni);
Service* service_found(NetworkInterface* ni, uint8_t protocol, uint32_t addr, uint16_t port);

void service_is_remove_grace(Service* service);
bool service_remove(Service* service, uint64_t wait);
bool service_remove_force(Service* service);
void service_dump();
#endif
