#ifndef __DNAT_H__
#define __DNAT_H__

#include "server.h"
#include "session.h"
#include "interface.h"

Session* dnat_tcp_session_alloc(Server* server, Map* private_interfaces, Interface* service_interface, Interface* client_interface);
Session* dnat_udp_session_alloc(Server* server, Map* private_interfaces, Interface* service_interface, Interface* client_interface);

#endif /*__DNAT_H__*/
