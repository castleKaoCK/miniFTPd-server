#ifndef	_COMMON_H
#define	_COMMON_H


#include<sys/types.h>
#include<pwd.h>
#include<sys/socket.h>
#include<unistd.h>
#include<crypt.h>
#include<shadow.h>
#include<pthread.h>
#include<signal.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<netdb.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<errno.h>
#include<sys/wait.h>
#include<sys/epoll.h>
#include<fcntl.h>
#include<ctype.h>
#include<shadow.h>

#include<time.h>
#include<sys/stat.h>
#include<dirent.h>
#include<sys/time.h>

#include<signal.h>
#include<linux/capability.h>
#include<sys/syscall.h>
#include<sys/sendfile.h>


#define ERR_EXIT(m) \
	do \
	{ \
		perror(m); \
		exit(EXIT_FAILURE); \
	} while(0) \

#define	MAX_COMMAND_LINE	1024
#define MAX_COMMAND	32
#define	MAX_ARG	1024

#define	MINIFTP_CONF	"miniftpd.conf"


#endif	//_COMMON_H
