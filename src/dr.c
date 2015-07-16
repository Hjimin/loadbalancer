#include <stdio.h>
#define DONT_MAKE_WRAPPER
#include <_malloc.h>
#undef DONT_MAKE_WRAPPER
#include <net/packet.h>
#include <net/ether.h>
#include <net/arp.h>

#include "dr.h"
#include "endpoint.h"
#include "session.h"
#include "server.h"

static bool dr_translate(Session* session, Packet* packet);
static bool dr_untranslate(Session* session, Packet* packet);
static bool dr_free(Session* session);

Session* dr_session_alloc(Endpoint* service_endpoint, Endpoint* server_endpoint, uint32_t public_addr, uint16_t public_port, uint32_t private_addr) {
	Session* session = __malloc(sizeof(Session), server_endpoint->ni->pool);
	if(!session) {
		printf("Can'nt allocate Session\n");
		return NULL;
	}

	session->server_endpoint = server_endpoint;
	session->service_endpoint = service_endpoint;

	session->event_id = 0;
	session->fin = false;

	session->translate = dr_translate;
	session->untranslate = dr_untranslate;
	session->free = dr_free;

	return session;
}

static bool dr_free(Session* session) {
	__free(session, session->server_endpoint->ni->pool);

	return true;
}

static bool dr_translate(Session* session, Packet* packet) {
	Ether* ether = (Ether*)(packet->buffer + packet->start);

	Endpoint* server_endpoint = session->server_endpoint;
	ether->smac = endian48(server_endpoint->ni->mac);
	ether->dmac = endian48(arp_get_mac(server_endpoint->ni, session->private_endpoint.addr, server_endpoint->addr));

	return true;
}

static bool dr_untranslate(Session* session, Packet* packet) {
	//do nothing
	return true;
}

