#ifndef __INTERFACE_H__
#define __INTERFACE_H__
#include <net/ni.h>
#include <util/types.h>

#define PN_LB_PRIVATE_INTERFACES	"pn.lb.private_interfaces"

typedef struct {
	uint8_t protocol;
	uint32_t addr;
	uint16_t port;
	NetworkInterface* ni;
	uint8_t ni_num;
	Map* tcp_ports;
	uint16_t tcp_next_port;
	Map* udp_ports;
	uint16_t udp_next_port;
} Interface;

Interface* interface_create(uint8_t protocol, uint32_t addr, uint16_t port, uint8_t ni_num);
void interface_delete(Interface* interface);

uint16_t interface_tcp_port_alloc(Interface* interface);
void interface_tcp_port_free(Interface* interface, uint16_t port);
uint16_t interface_udp_port_alloc(Interface* interface);
void interface_udp_port_free(Interface* interface, uint16_t port);
#endif /* __INTERFACE_H__ */
