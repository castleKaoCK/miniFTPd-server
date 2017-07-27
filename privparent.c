#include "privparent.h"
#include "privsock.h"
#include "sysutil.h"
#include "tunable.h"



static void privop_pasv_get_data_sock(session_t *sess);
static void privop_pasv_active(session_t *sess);
static void privop_pasv_listen(session_t *sess);
static void privop_pasv_accept(session_t *sess);

int capset(cap_user_header_t hdrp, const cap_user_data_t datap)
{
	return syscall(__NR_capset, hdrp, datap);	//系统调用capset
}

void minimize_privilege(void)
{
	//转换成nobody用户
	struct passwd *pw = getpwnam("nobody");	//得到用户nobody的信息
	if(pw == NULL)
		return ;

	if(setegid(pw->pw_gid) < 0)	//设置当前进程有效组ID
		ERR_EXIT("setegid");
	if(seteuid(pw->pw_uid) < 0)	//设置当前进程有效用户ID
		ERR_EXIT("seteuid");
	

	struct __user_cap_header_struct	cap_header;
	struct __user_cap_data_struct	cap_data;
	
	memset(&cap_header, 0, sizeof(cap_header));
	memset(&cap_data, 0, sizeof(cap_data));
	
	cap_header.version = _LINUX_CAPABILITY_VERSION_1;
	cap_header.pid = 0;

	__u32 cap_mask = 0;
	cap_mask |= (1 << CAP_NET_BIND_SERVICE);
	cap_data.effective = cap_data.permitted = cap_mask;
	cap_data.inheritable = 0;

	capset(&cap_header, &cap_data);
}

/*
 *	父进程：nobody进程
 */
void handle_parent(session_t *sess)
{

	minimize_privilege();

	char cmd;
	while(1)
	{
		//read(sess->parent_fd, &cmd, 1);
		//接收服务子进程内部命令
		//子进程套接字关闭时，父进程会在priv_sock_get_cmd关闭
		cmd = priv_sock_get_cmd(sess->parent_fd);	
		//解析内部命令
		//处理内部命令

		switch(cmd)
		{
			case PRIV_SOCK_GET_DATA_SOCK: privop_pasv_get_data_sock(sess);
				break;
			case PRIV_SOCK_PASV_ACTIVE: privop_pasv_active(sess);
				break;
			case PRIV_SOCK_PASV_LISTEN: privop_pasv_listen(sess);
				break;
			case PRIV_SOCK_PASV_ACCEPT: privop_pasv_accept(sess);
				break;
		}

	}
}


static void privop_pasv_get_data_sock(session_t *sess)
{
	//接收服务进程传来的端口
	unsigned short port = (unsigned short)priv_sock_get_int(sess->parent_fd);
	//接收服务进程传来的IP字符串
	char ip[16] = {0};
	priv_sock_recv_buf(sess->parent_fd, ip, sizeof(ip));
	

	printf("%u  %s\n",port, ip);


	//连接客户端
	struct sockaddr_in addr;
	memset(&addr, 0,sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = (unsigned long)inet_addr(ip);

	int fd = tcp_client(20);	//绑定20端口号
	

	if(fd == -1)	//套接字创建失败，给子进程失败应答
	{
		priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_BAD);
		return ;
	}
	if(connect_timeout(fd, &addr, tunable_connect_timeout) < 0)	//数据连接失败，给子进程失败应答
	{
		printf("connect fail\n");
		priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_BAD);
		close(fd);
		return ;
	}

	//给服务进程一个连接成功的应答，返回数据连接套接字
	priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_OK);
	priv_sock_send_fd(sess->parent_fd, fd);
	close(fd);

}
static void privop_pasv_active(session_t *sess)
{
	int active;
	if(sess->pasv_listen_fd != -1)
	{
		active = 1;
	}
	else
	{
		active = 0;
	}

	priv_sock_send_int(sess->parent_fd, active);
}
static void privop_pasv_listen(session_t *sess)
{
	char ip[16] = {0};
	getLocalIP(ip);

	sess->pasv_listen_fd = tcp_server(ip, 0);	//创建被动模式监听套接字
	struct sockaddr_in addr;
	socklen_t addrlen = sizeof(addr);
	if(getsockname(sess->pasv_listen_fd, (struct sockaddr *)&addr, &addrlen) < 0)
	{
		ERR_EXIT("getsockname");
	}

	unsigned short port = ntohs(addr.sin_port);

	priv_sock_send_int(sess->parent_fd, (int)port);
}
static void privop_pasv_accept(session_t *sess)
{
	int fd = accept_timeout(sess->pasv_listen_fd, NULL, tunable_accept_timeout);
	close(sess->pasv_listen_fd);
	sess->pasv_listen_fd = -1;	

	if(fd == -1)	//接收套接字失败
	{
		priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_BAD);
		return ;
	}

	priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_OK);
	priv_sock_send_fd(sess->parent_fd, fd);
	close(fd);
}
