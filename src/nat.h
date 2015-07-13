#ifndef __NAT_H__
#define __NAT_H__

#include "session.h"
#include "server.h"
#include "interface.h"

Session* nat_tcp_session_alloc(Server* server, Map* private_interfaces, Interface* service_interface, Interface* client_interface);
Session* nat_udp_session_alloc(Server* server, Map* private_interfaces, Interface* service_interface, Interface* client_interface);

#endif /*__NAT_H__*/
