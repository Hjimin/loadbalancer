#ifndef __NAT_H__
#define __NAT_H__

#include "server.h"
#include "session.h"
#include "endpoint.h"

Session* nat_tcp_session_alloc(Endpoint* server_endpoint, Endpoint* service_endpoint, uint32_t public_addr, uint16_t public_port, uint32_t private_addr);
Session* nat_udp_session_alloc(Endpoint* server_endpoint, Endpoint* service_endpoint, uint32_t public_addr, uint16_t public_port, uint32_t private_addr);

#endif /*__NAT_H__*/
