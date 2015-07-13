#include <stdio.h>
#include <malloc.h>
#include <net/packet.h>
#include <net/ether.h>
#include <net/arp.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>

#include "dnat.h"
#include "interface.h"
#include "service.h"
#include "server.h"
#include "session.h"

static bool dnat_free(Session* session);
static bool dnat_tcp_pack(Session* session, Packet* packet);
static bool dnat_udp_pack(Session* session, Packet* packet);
static bool dnat_tcp_unpack(Session* session, Packet* packet);
static bool dnat_udp_unpack(Session* session, Packet* packet);

Session* dnat_tcp_session_alloc(Server* server, Map* private_interfaces, Interface* service_interface, Interface* client_interface) {
	Session* session = malloc(sizeof(Session));
	if(!session) {
		printf("Can'nt allocate Session\n");
		return NULL;
	}

	session->server_interface = server->server_interface;
	session->service_interface = service_interface;
	session->client_interface = client_interface;
	session->private_interface = NULL;

	session->loadbalancer_pack = dnat_tcp_pack;
	session->loadbalancer_unpack = dnat_tcp_unpack;
	session->session_free = dnat_free;

	return session;
}

Session* dnat_udp_session_alloc(Server* server, Map* private_interfaces, Interface* service_interface, Interface* client_interface) {
	Session* session = malloc(sizeof(Session));
	if(!session) {
		printf("Can'nt allocate Session\n");
		return NULL;
	}

	session->server_interface = server->server_interface;
	session->service_interface = service_interface;
	session->client_interface = client_interface;
	session->private_interface = NULL;

	session->loadbalancer_pack = dnat_udp_pack;
	session->loadbalancer_unpack = dnat_udp_unpack;
	session->session_free = dnat_free;

	return session;
}

static bool dnat_free(Session* session) {
	interface_delete(session->client_interface);
	free(session);

	return true;
}

static bool dnat_tcp_pack(Session* session, Packet* packet) {
	Interface* server_interface = session->server_interface;
	Ether* ether = (Ether*)(packet->buffer + packet->start);
	IP* ip = (IP*)ether->payload;
	TCP* tcp = (TCP*)ip->body;

	ether->smac = endian48(server_interface->ni->mac);
	ether->dmac = endian48(server_arp_get_mac(server_interface->ni, session->client_interface->addr, server_interface->addr));

	ip->destination = endian32(server_interface->addr);
	tcp->destination = endian16(server_interface->port);

	tcp_pack(packet, endian16(ip->length) - ip->ihl * 4 - TCP_LEN);
	if(session->fin && tcp->ack) {
		session_free(session);
	}

	return true;
}

static bool dnat_udp_pack(Session* session, Packet* packet) {
	Interface* server_interface = session->server_interface;
	Ether* ether = (Ether*)(packet->buffer + packet->start);
	IP* ip = (IP*)ether->payload;
	UDP* udp = (UDP*)ip->body;

	ether->smac = endian48(server_interface->ni->mac);
	ether->dmac = endian48(server_arp_get_mac(server_interface->ni, session->client_interface->addr, server_interface->addr));

	ip->destination = endian32(server_interface->addr);
	udp->destination = endian16(server_interface->port);

	udp_pack(packet, endian16(ip->length) - ip->ihl * 4 - UDP_LEN);

	return true;
}

static bool dnat_tcp_unpack(Session* session, Packet* packet) {
	Interface* service_interface = session->service_interface;
	Ether* ether = (Ether*)(packet->buffer + packet->start);
	IP* ip = (IP*)ether->payload;
	TCP* tcp = (TCP*)ip->body;

	ether->smac = endian48(service_interface->ni->mac);
	ether->dmac = endian48(arp_get_mac(service_interface->ni, endian32(ip->destination)));
	ip->source = endian32(service_interface->addr);
	tcp->source = endian16(service_interface->port);
		
	if(tcp->fin) {
		session_set_fin(session);
	}

	tcp_pack(packet, endian16(ip->length) - ip->ihl * 4 - TCP_LEN);

	return true;
}

static bool dnat_udp_unpack(Session* session, Packet* packet) {
	Interface* service_interface = session->service_interface;
	Ether* ether = (Ether*)(packet->buffer + packet->start);
	IP* ip = (IP*)ether->payload;
	UDP* udp = (UDP*)ip->body;

	ether->smac = endian48(service_interface->ni->mac);
	ether->dmac = endian48(arp_get_mac(service_interface->ni, endian32(ip->destination)));
	ip->source = endian32(service_interface->addr);
	udp->source = endian16(service_interface->port);

	udp_pack(packet, endian16(ip->length) - ip->ihl * 4 - UDP_LEN);

	return true;
}
