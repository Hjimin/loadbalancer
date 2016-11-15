#ifndef __INTERFACE_H__
#define __INTERFACE_H__
#include <util/types.h>
#include <net/nic.h>

typedef struct _Endpoint {
	NIC*	ni;
	uint32_t		addr;
	uint8_t			protocol;
	uint16_t		port;
	int				ni_num;
} Endpoint;

Endpoint* endpoint_alloc(NIC* ni, uint32_t addr, uint8_t protocol, uint16_t port);
bool endpoint_free(NIC* ni, Endpoint* endpoint);
#endif /* __INTERFACE_H__ */
