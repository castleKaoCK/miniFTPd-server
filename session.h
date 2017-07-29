#ifndef _SESSION_H_
#define _SESSION_H_

#include "common.h"

/*
 *	新会话的必要信息
 */
typedef struct session{
	//控制连接
	uid_t uid;
	int ctrl_fd;	//已连接的控制连接套接字
	char cmdline[MAX_COMMAND_LINE];
	char cmd[MAX_COMMAND];
	char arg[MAX_ARG];
	
	//数据连接
	struct sockaddr_in *port_addr;	//将要连接的数据连接地址
	int pasv_listen_fd;	//被动模式的监听套接字
	int data_fd;	//根据数据连接地址创建的套接字
	int data_process;	//当前是否处于数据传输状态

	//限速
	unsigned int bw_upload_rate_max;
	unsigned int bw_download_rate_max;
	long bw_transfer_start_sec;	//开始传输的时间
	long bw_transfer_start_usec;

	//父子进程通道
	int parent_fd;
	int child_fd;

	//FTP协议状态
	int is_ascii;
	long long restart_pos;
	char * rnfr_name;
	int abor_received;

	//连接数限制
	unsigned int num_clients;
	unsigned int num_this_ip;
} session_t;


void begin_session(session_t *sess);	//为一个客户端连接新建一个会话

#endif	//_SESSION_H_

