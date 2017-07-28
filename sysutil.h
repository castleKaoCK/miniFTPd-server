#ifndef _SYSUTIL_H
#define _SYSUTIL_H

#include "common.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <sys/ioctl.h>
#include <netinet/in.h>


int tcp_client(unsigned short port);	//创建数据套接字
int tcp_server(const char *host, unsigned short port);	//创建套接字、绑定、监听


int	getlocalip(char *ip);
void getLocalIP(char*);

void activate_nonblock(int fd);	//设置I/O为非阻塞模式
void deactivate_nonblock(int fd); //设置为阻塞模式

int read_timeout(int fd,unsigned int wait_seconds);	//读超时检测函数
int write_timeout(int fd,unsigned int wait_seconds);//写超时检测函数
int accept_timeout(int fd,struct sockaddr_in *addr,unsigned int wait_seconds);	//带超时的accept函数
int connect_timeout(int fd,struct sockaddr_in *addr,unsigned int wait_seconds);	//带超时的connect函数

ssize_t readn(int fd,void *buf,size_t count);
ssize_t	writen(int fd,const void *buf,size_t count);

ssize_t	recv_peek(int sockfd,void *buf,size_t len);

ssize_t readline(int sockfd,void *buf,size_t maxline);

void send_fd(int sock_fd , int fd);
int recv_fd(const int sock_fd);

const char * statbuf_get_perms(struct stat *sbuf);
const char * statbuf_get_date(struct stat *sbuf);

int lock_file_read(int fd);		//加读锁
int lock_file_write(int fd);	//加写锁
int unlock_file(int fd);		//解锁

long get_time_sec(void);
long get_time_usec(void);
void nano_sleep(double seconds);	//指定进程睡眠时间

void activate_oobinline(int fd);	//开启fd接收带外数据的功能
void activate_sigurg(int fd);		//设定当前进程能够接收fd文件描述符产生的SIGURG信号

#endif	//_SYSUTIL_H
