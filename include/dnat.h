#ifndef __DNAT_H__
#define __DNAT_H__

#include "server.h"
#include "endpoint.h"
#include "session.h"

Session* dnat_tcp_session_alloc(Endpoint* server_endpoint, Endpoint* service_endpoint, uint32_t public_addr, uint16_t public_port, uint32_t private_addr);
Session* dnat_udp_session_alloc(Endpoint* server_endpoint, Endpoint* service_endpoint, uint32_t public_addr, uint16_t public_port, uint32_t private_addr);

#endif /*__DNAT_H__*/
