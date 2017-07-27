#include "common.h"
#include "session.h"
#include "ftpproto.h"
#include "privparent.h"
#include "privsock.h"

void begin_session(session_t *sess)
{
	/*
	int sockfds[2];	//父子进程通信套接字
	if( socketpair(PF_UNIX, SOCK_STREAM, 0, sockfds) < 0)
		ERR_EXIT("socketpair");
	*/
	priv_sock_init(sess);	//父子进程通信初始化

	pid_t	pid;
	pid = fork();
	if(pid < 0)
		ERR_EXIT("fork");

	if(pid == 0)	//子进程
	{	
		//ftp服务进程
		/*
		close(sockfds[0]);	//关闭不需要的文件描述符
		sess->child_fd = sockfds[1];
		*/
		printf("child\n");
		priv_sock_set_child_context(sess);
		handle_child(sess);
	}
	else
	{	
		//nobody进程

		/*
		close(sockfds[1]);	//关闭不需要的文件描述符
		sess->parent_fd = sockfds[0];
		*/
		printf("parent\n");
		priv_sock_set_parent_context(sess);
		handle_parent(sess);
	}
}
