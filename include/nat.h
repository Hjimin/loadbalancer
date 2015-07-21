#ifndef __NAT_H__
#define __NAT_H__

#include "server.h"
#include "session.h"
#include "endpoint.h"

Session* nat_tcp_session_alloc(Endpoint* server_endpoint, Endpoint* service_endpoint, Endpoint* client_endpoint, Endpoint* private_endpoint);
Session* nat_udp_session_alloc(Endpoint* server_endpoint, Endpoint* service_endpoint, Endpoint* client_endpoint, Endpoint* private_endpoint);

#endif /*__NAT_H__*/
