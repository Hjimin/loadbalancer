#include <malloc.h>
#include <net/ni.h>

#include "interface.h"

Interface* interface_create(uint8_t protocol, uint32_t addr, uint16_t port, uint8_t ni_num) {
	NetworkInterface* ni = ni_get(ni_num);
	if(ni == NULL)
		return NULL;

	Interface* interface = malloc(sizeof(Interface));
	interface->protocol = protocol;
	interface->addr = addr;
	interface->port = port;
	interface->ni = ni;

	return interface;

}

void interface_delete(Interface* interface) {
	free(interface);
}
