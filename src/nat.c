#include <stdio.h>
#include <malloc.h>
#include <util/map.h>
#include <net/packet.h>
#include <net/ether.h>
#include <net/arp.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>

#include "nat.h"
#include "interface.h"
#include "session.h"

static bool nat_tcp_pack(Session* session, Packet* packet);
static bool nat_udp_pack(Session* session, Packet* packet);
static bool nat_tcp_unpack(Session* session, Packet* packet);
static bool nat_udp_unpack(Session* session, Packet* packet);
static bool nat_tcp_free(Session* session);
static bool nat_udp_free(Session* session);

Session* nat_tcp_session_alloc(Interface* server_interface, Map* private_interfaces, Interface* service_interface, Interface* client_interface) {
	Session* session = malloc(sizeof(Session));
	if(!session) {
		printf("Can'nt allocate Session\n");
		return NULL;
	}

	session->server_interface = server_interface;
	session->service_interface = service_interface;
	session->client_interface = client_interface;

	Interface* private_interface = map_get(private_interfaces, server_interface->ni);

	uint16_t tcp_port = interface_tcp_port_alloc(private_interface);
	session->private_interface = interface_create(IP_PROTOCOL_TCP, private_interface->addr, tcp_port, private_interface->ni_num);
	if(!session->private_interface) {
		interface_tcp_port_free(private_interface, tcp_port);

		goto error_private_interface_create;
	}

	session->loadbalancer_pack = nat_tcp_pack;
	session->loadbalancer_unpack = nat_tcp_unpack;
	session->session_free = nat_tcp_free;

	return session;

error_private_interface_create:
	free(session);

	return NULL;
}

Session* nat_udp_session_alloc(Interface* server_interface, Map* private_interfaces, Interface* service_interface, Interface* client_interface) {
	Session* session = malloc(sizeof(Session));
	if(!session) {
		printf("Can'nt allocate Session\n");
		return NULL;
	}

	session->server_interface = server_interface;
	session->service_interface = service_interface;
	session->client_interface = client_interface;

	Interface* private_interface = map_get(private_interfaces, server_interface->ni);

	uint16_t udp_port = interface_udp_port_alloc(private_interface);
	session->private_interface = interface_create(IP_PROTOCOL_UDP, private_interface->addr, udp_port, private_interface->ni_num);
	if(!session->private_interface) {
		interface_udp_port_free(private_interface, udp_port);

		goto error_private_interface_create;
	}

	session->loadbalancer_pack = nat_udp_pack;
	session->loadbalancer_unpack = nat_udp_unpack;
	session->session_free = nat_udp_free;

	return session;

error_private_interface_create:
	free(session);

	return NULL;
}

static bool nat_tcp_free(Session* session) {
	Interface* private_interface = session->private_interface;
	interface_tcp_port_free(private_interface, private_interface->port);
	interface_delete(session->private_interface);
	interface_delete(session->client_interface);

	free(session);

	return true;
}

static bool nat_udp_free(Session* session) {
	Interface* private_interface = session->private_interface;
	interface_udp_port_free(private_interface, private_interface->port);
	interface_delete(session->private_interface);
	interface_delete(session->client_interface);

	free(session);

	return true;
}

static bool nat_tcp_pack(Session* session, Packet* packet) {
	Interface* server_interface = session->server_interface;
	Ether* ether = (Ether*)(packet->buffer + packet->start);
	IP* ip = (IP*)ether->payload;
	TCP* tcp = (TCP*)ip->body;

	ether->smac = endian48(server_interface->ni->mac);
	ether->dmac = endian48(server_arp_get_mac(server_interface->ni, session->private_interface->addr, server_interface->addr));
	ip->source = endian32(session->private_interface->addr);
	ip->destination = endian32(server_interface->addr);
	tcp->source = endian16(session->private_interface->port);
	tcp->destination = endian16(server_interface->port);

	tcp_pack(packet, endian16(ip->length) - ip->ihl * 4 - TCP_LEN);
	if(session->fin && tcp->ack) {
		session_free(session);
	}
	return true;
}

static bool nat_udp_pack(Session* session, Packet* packet) {
	Interface* server_interface = session->server_interface;
	Ether* ether = (Ether*)(packet->buffer + packet->start);
	IP* ip = (IP*)ether->payload;
	UDP* udp = (UDP*)ip->body;

	ether->smac = endian48(server_interface->ni->mac);
	ether->dmac = endian48(server_arp_get_mac(server_interface->ni, session->private_interface->addr, server_interface->addr));
	ip->source = endian32(session->private_interface->addr);
	ip->destination = endian32(server_interface->addr);
	udp->source = endian16(session->private_interface->port);
	udp->destination = endian16(server_interface->port);

	udp_pack(packet, endian16(ip->length) - ip->ihl * 4 - UDP_LEN);

	return true;
}

static bool nat_tcp_unpack(Session* session, Packet* packet) {
	Interface* service_interface = session->service_interface;
	Ether* ether = (Ether*)(packet->buffer + packet->start);
	IP* ip = (IP*)ether->payload;
	TCP* tcp = (TCP*)ip->body;

	ether->smac = endian48(service_interface->ni->mac);
	ether->dmac = endian48(arp_get_mac(session->client_interface->ni, session->client_interface->addr));
	ip->source = endian32(service_interface->addr);
	ip->destination = endian32(session->client_interface->addr);
	tcp->source = endian16(service_interface->port);
	tcp->destination = endian16(session->client_interface->port);

	tcp_pack(packet, endian16(ip->length) - ip->ihl * 4 - TCP_LEN);
	if(tcp->fin) {
		session_set_fin(session);
	}
	return true;
}

static bool nat_udp_unpack(Session* session, Packet* packet) {
	Interface* service_interface = session->service_interface;
	Ether* ether = (Ether*)(packet->buffer + packet->start);
	IP* ip = (IP*)ether->payload;
	UDP* udp = (UDP*)ip->body;

	ether->smac = endian48(service_interface->ni->mac);
	ether->dmac = endian48(arp_get_mac(session->client_interface->ni, session->client_interface->addr));
	ip->source = endian32(service_interface->addr);
	ip->destination = endian32(session->client_interface->addr);
	udp->source = endian16(service_interface->port);
	udp->destination = endian16(session->client_interface->port);

	udp_pack(packet, endian16(ip->length) - ip->ihl * 4 - UDP_LEN);

	return true;
}
