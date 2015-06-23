#ifndef __INTERFACE_H__
#define __INTERFACE_H__
#include <net/ni.h>
#include <util/types.h>

typedef struct {
	uint8_t protocol;
	uint32_t addr;
	uint16_t port;
	NetworkInterface* ni;
	uint8_t ni_num;
} Interface;

Interface* interface_create(uint8_t protocol, uint32_t addr, uint16_t port, uint8_t ni_num);
void interface_delete(Interface* interface);

#endif /* __INTERFACE_H__ */
