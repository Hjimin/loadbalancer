#ifndef __DNAT_H__
#define __DNAT_H__

#include "server.h"
#include "endpoint.h"
#include "session.h"

Session* dnat_tcp_session_alloc(Endpoint* server_endpoint, Endpoint* service_endpoint, Endpoint* client_endpoint, Endpoint* private_endpoint);
Session* dnat_udp_session_alloc(Endpoint* server_endpoint, Endpoint* service_endpoint, Endpoint* client_endpoint, Endpoint* private_endpoint);

#endif /*__DNAT_H__*/
