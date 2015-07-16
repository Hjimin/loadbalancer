#ifndef __INTERFACE_H__
#define __INTERFACE_H__
#include <util/types.h>
#include <net/ni.h>

typedef struct _Endpoint {
	NetworkInterface*	ni;
	uint32_t		addr;
	uint8_t			protocol;
	uint16_t		port;
} Endpoint;

Endpoint* endpoint_alloc(NetworkInterface* ni, uint32_t addr, uint8_t protocol, uint16_t port);
bool endpoint_free(NetworkInterface* ni, Endpoint* endpoint);
#endif /* __INTERFACE_H__ */
