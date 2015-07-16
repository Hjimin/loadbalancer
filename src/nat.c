#include <stdio.h>
#define DONT_MAKE_WRAPPER
#include <_malloc.h>
#undef DONT_MAKE_WRAPPER
#include <util/map.h>
#include <net/packet.h>
#include <net/ether.h>
#include <net/arp.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>

#include "nat.h"
#include "endpoint.h"
#include "session.h"

static bool nat_tcp_translate(Session* session, Packet* packet);
static bool nat_udp_translate(Session* session, Packet* packet);
static bool nat_tcp_untranslate(Session* session, Packet* packet);
static bool nat_udp_untranslate(Session* session, Packet* packet);
static bool nat_tcp_free(Session* session);
static bool nat_udp_free(Session* session);

Session* nat_tcp_session_alloc(Server* server, Endpoint* service_endpoint, uint32_t public_addr, uint16_t public_port, uint32_t private_addr) {
	Session* session = __malloc(sizeof(Session), server->ni->pool);
	if(!session) {
		printf("Can'nt allocate Session\n");
		return NULL;
	}

	session->service_ni = service->ni;
	session->server_ni = server->ni;

	session->service_endpoint = service_endpoint;
	session->server_endpoint = server->server_endpoint;

	session->public_endpoint.protocol = IP_PROTOCOL_TCP;
	session->public_endpoint.addr = public_addr;
	session->public_endpoint.port = public_port;

	session->private_endpoint.protocol = IP_PROTOCOL_TCP;
	session->private_endpoint.addr = private_addr;
	session->private_endpoint.port = tcp_port_alloc(server->ni, private_addr);

	session->event_id = 0;
	session->fin = false;

	session->translate = nat_tcp_translate;
	session->untranslate = nat_tcp_untranslate;
	session->free = nat_tcp_free;

	return session;
}

Session* nat_udp_session_alloc(Server* server, Endpoint* service_endpoint, uint32_t public_addr, uint16_t public_port, uint32_t private_addr) {
	Session* session = __malloc(sizeof(Session), server->ni->pool);
	if(!session) {
		printf("Can'nt allocate Session\n");
		return NULL;
	}

	session->service_ni = service->ni;
	session->server_ni = server->ni;

	session->service_endpoint = service_endpoint;
	session->server_endpoint = server_endpoint;

	session->public_endpoint.protocol = IP_PROTOCOL_UDP;
	session->public_endpoint.addr = public_addr;
	session->public_endpoint.port = public_port;

	session->private_endpoint.protocol = IP_PROTOCOL_UDP;
	session->private_endpoint.addr = private_addr;
	session->private_endpoint.port = udp_port_alloc(server->ni, private_addr);

	session->event_id = 0;
	session->fin = false;

	session->translate = nat_udp_translate;
	session->untranslate = nat_udp_untranslate;
	session->free = nat_udp_free;

	return session;
}

static bool nat_tcp_free(Session* session) {
	tcp_port_free(session->server_ni, session->private_endpoint.port);
	free(session);

	return true;
}

static bool nat_udp_free(Session* session) {
	udp_port_free(session->server_ni, session->private_endpoint.port);
	free(session);

	return true;
}

static bool nat_tcp_translate(Session* session, Packet* packet) {
	Endpoint* server_endpoint = session->server_endpoint;
	Ether* ether = (Ether*)(packet->buffer + packet->start);
	IP* ip = (IP*)ether->payload;
	TCP* tcp = (TCP*)ip->body;

	ether->smac = endian48(session->server_ni->mac);
	ether->dmac = endian48(arp_get_mac(session->server_ni, session->private_endpoint.addr, server_endpoint->addr));
	ip->source = endian32(session->private_endpoint.addr);
	ip->destination = endian32(server_endpoint->addr);
	tcp->source = endian16(session->private_endpoint.port);
	tcp->destination = endian16(server_endpoint->port);

	tcp_pack(packet, endian16(ip->length) - ip->ihl * 4 - TCP_LEN);
	if(session->fin && tcp->ack) {
		session_free(session);
	}
	return true;
}

static bool nat_udp_translate(Session* session, Packet* packet) {
	Endpoint* server_endpoint = session->server_endpoint;
	Ether* ether = (Ether*)(packet->buffer + packet->start);
	IP* ip = (IP*)ether->payload;
	UDP* udp = (UDP*)ip->body;

	ether->smac = endian48(session->server_ni->mac);
	ether->dmac = endian48(arp_get_mac(session->server_ni, session->private_endpoint.addr, server_endpoint->addr));
	ip->source = endian32(session->private_endpoint.addr);
	ip->destination = endian32(server_endpoint->addr);
	udp->source = endian16(session->private_endpoint.port);
	udp->destination = endian16(server_endpoint->port);

	udp_pack(packet, endian16(ip->length) - ip->ihl * 4 - UDP_LEN);

	return true;
}

static bool nat_tcp_untranslate(Session* session, Packet* packet) {
	Endpoint* service_endpoint = session->service_endpoint;
	Ether* ether = (Ether*)(packet->buffer + packet->start);
	IP* ip = (IP*)ether->payload;
	TCP* tcp = (TCP*)ip->body;

	ether->smac = endian48(session->service_ni->mac);
	ether->dmac = endian48(arp_get_mac(session->service_ni, session->public_endpoint.addr, session->private_endpoint.addr));
	ip->source = endian32(service_endpoint->addr);
	ip->destination = endian32(session->public_endpoint.addr);
	tcp->source = endian16(service_endpoint->port);
	tcp->destination = endian16(session->public_endpoint.port);

	tcp_pack(packet, endian16(ip->length) - ip->ihl * 4 - TCP_LEN);
	if(tcp->fin) {
		session_set_fin(session);
	}
	return true;
}

static bool nat_udp_untranslate(Session* session, Packet* packet) {
	Endpoint* service_endpoint = session->service_endpoint;
	Ether* ether = (Ether*)(packet->buffer + packet->start);
	IP* ip = (IP*)ether->payload;
	UDP* udp = (UDP*)ip->body;

	ether->smac = endian48(session->service_ni->mac);
	ether->dmac = endian48(arp_get_mac(session->service_ni, session->public_endpoint.addr, session->private_endpoint.addr));
	ip->source = endian32(service_endpoint->addr);
	ip->destination = endian32(session->public_endpoint.addr);
	udp->source = endian16(service_endpoint->port);
	udp->destination = endian16(session->public_endpoint.port);

	udp_pack(packet, endian16(ip->length) - ip->ihl * 4 - UDP_LEN);

	return true;
}
