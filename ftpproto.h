#ifndef	_FTP_PROTO_H_
#define	_FTP_PROTO_H_

#include "session.h"
void handle_child(session_t *sess);


int list_common(session_t *sess, int detail);


#endif	//_FTP_PROTO_H_
