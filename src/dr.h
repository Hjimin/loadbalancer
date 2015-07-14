#ifndef __DR_H__
#define __DR_H__

#include "server.h"
#include "session.h"
#include "interface.h"

Session* dr_session_alloc(Interface* server_interface, Map* private_interfaces, Interface* service_interface, Interface* client_interface);

#endif /*__DR_H__*/
