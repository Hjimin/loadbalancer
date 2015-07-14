#include <stdio.h>
#include <malloc.h>
#include <net/packet.h>
#include <net/ether.h>

#include "dr.h"
#include "interface.h"
#include "session.h"
#include "server.h"

static bool dr_pack(Session* session, Packet* packet);
static bool dr_unpack(Session* session, Packet* packet);
static bool dr_session_free(Session* session);

Session* dr_session_alloc(Interface* server_interface, Map* private_interfaces, Interface* service_interface, Interface* client_interface) {
	Session* session = malloc(sizeof(Session));
	if(!session) {
		printf("Can'nt allocate Session\n");
		return NULL;
	}

	session->server_interface = server_interface;
	session->service_interface = service_interface;
	session->client_interface = client_interface;
	session->private_interface = interface_create(client_interface->protocol, client_interface->addr, client_interface->port, client_interface->ni_num);

	session->loadbalancer_pack = dr_pack;
	session->loadbalancer_unpack = dr_unpack;
	session->session_free = dr_session_free;

	return session;
}

static bool dr_session_free(Session* session) {
	interface_delete(session->client_interface);
	interface_delete(session->private_interface);

	free(session);

	return true;
}

static bool dr_pack(Session* session, Packet* packet) {
	Ether* ether = (Ether*)(packet->buffer + packet->start);

	Interface* server_interface = session->server_interface;
	ether->smac = endian48(server_interface->ni->mac);
	ether->dmac = endian48(server_arp_get_mac(server_interface->ni, session->private_interface->addr, server_interface->addr));

	return true;
}

static bool dr_unpack(Session* session, Packet* packet) {
	//do nothing
	return true;
}

