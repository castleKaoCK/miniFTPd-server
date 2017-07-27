#include "privsock.h"
#include "common.h"
#include "sysutil.h"


void priv_sock_init(session_t *sess)
{
	int sockfds[2];	//父子进程通信套接字
	if( socketpair(PF_UNIX, SOCK_STREAM, 0, sockfds) < 0)
		ERR_EXIT("socketpair");

	//套接字对
	sess->parent_fd = sockfds[0];
	sess->child_fd = sockfds[1];
	printf("parent_fd:%d     child_fd:%d\n", sess->parent_fd, sess->child_fd);


}
void priv_sock_close(session_t *sess)
{
	if(sess->child_fd != -1)
	{
		close(sess->child_fd);	//关闭不需要的子进程文件描述符
		sess->child_fd = -1;
	}
	if(sess->parent_fd != -1)
	{
		close(sess->parent_fd);	//关闭不需要的父进程文件描述符
		sess->parent_fd = -1;
	}
}
void priv_sock_set_parent_context(session_t *sess)
{
	if(sess->child_fd != -1)
	{
		printf("priv_sock parent_fd:%d\n",sess->parent_fd);
		close(sess->child_fd);	//关闭不需要的子进程文件描述符
		sess->child_fd = -1;
	}
}
void priv_sock_set_child_context(session_t *sess)
{
	if(sess->parent_fd != -1)
	{
		printf("priv_sock child_fd:%d\n",sess->child_fd);
		close(sess->parent_fd);	//关闭不需要的父进程文件描述符
		sess->parent_fd = -1;
	}
}


void priv_sock_send_cmd(int fd, char cmd)
{
	int ret;
	printf("fd:%d\n",fd);
	ret = writen(fd, &cmd, sizeof(cmd));
	if(ret != sizeof(cmd))
	{
		printf("ret ; %d  errno:%d\n", ret, errno);
		fprintf(stderr, "priv_sock_send_cmd error\n");
		exit(EXIT_FAILURE);
	}
}
char priv_sock_get_cmd(int fd)
{
	char res;
	int ret;
	printf("priv_sock_get_cmd fd: %d\n", fd);
	ret = readn(fd, &res, sizeof(res));
	
	if(ret == 0 )
	{
		fprintf(stdout, "priv_sock_get_cmd: service process quit\n");
		exit(EXIT_SUCCESS);
	}
	else if(ret != sizeof(res))
	{
		fprintf(stderr, "priv_sock_get_cmd error\n");
		exit(EXIT_FAILURE);
	}

	return res;
}
void priv_sock_send_result(int fd, char res)
{
	int ret;
	ret = writen(fd, &res, sizeof(res));
	if(ret != sizeof(res))
	{
		fprintf(stderr, "priv_sock_send_result error\n");
		exit(EXIT_FAILURE);
	}
}
char priv_sock_get_result(int fd)
{
	char res;
	int ret;
	ret = readn(fd, &res, sizeof(res));
	if(ret != sizeof(res))
	{
		fprintf(stderr, "priv_sock_get_result error\n");
		exit(EXIT_FAILURE);
	}

	return res;
}


void 	priv_sock_send_int(int fd, int the_int)	//发送一个整数
{
	int ret;
	ret = writen(fd, &the_int, sizeof(the_int));
	if(ret != sizeof(the_int))
	{
		fprintf(stderr, "priv_sock_send_int error\n");
		exit(EXIT_FAILURE);
	}
}
int		priv_sock_get_int(int fd)					//接收一个整数
{
	int the_int;
	int ret;
	ret = readn(fd, &the_int, sizeof(the_int));
	if(ret != sizeof(the_int))
	{
		fprintf(stderr, "priv_sock_get_int error\n");
		exit(EXIT_FAILURE);
	}

	return the_int;
}
void 	priv_sock_send_buf(int fd, const char *buf, unsigned int len)	//发送一个字符串
{
	priv_sock_send_int(fd, (int)len);	//发送长度
	int ret = writen(fd, buf, len);
	if(ret != (int)len)
	{
		fprintf(stderr, "priv_sock_send_buf error\n");
		exit(EXIT_FAILURE);
	}
}
void 	priv_sock_recv_buf(int fd, char *buf, unsigned int len)	//接收一个字符串
{
	unsigned int recv_len = (unsigned int)priv_sock_get_int(fd);
	if(recv_len > len)
	{
		fprintf(stderr, "priv_sock_recv_buf error\n");
		exit(EXIT_FAILURE);
	}

	int ret = readn(fd, buf, recv_len);
	if(ret != (int)recv_len)
	{
		fprintf(stderr, "priv_sock_recv_buf error\n");
		exit(EXIT_FAILURE);
	}
}
void 	priv_sock_send_fd(int sock_fd, int fd)	//发送文件描述符
{
	send_fd(sock_fd, fd);
}
int 	priv_sock_recv_fd(int sock_fd)		//接收文件描述符
{
	return recv_fd(sock_fd);
}

