#include "sysutil.h"





/*
 *	tcp_client - 创建数据套接字
 *	@port:绑定的端口号，0为不绑定端口
 *	返回值为创建的数据套接字
 */
int tcp_client(unsigned short port)
{
	int sock;
	if((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0)
		ERR_EXIT("tcp_client");
	
	if(port > 0)
	{
		int on = 1;
		if((setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&on, sizeof(on))) < 0)
			ERR_EXIT("setsockopt");

		char ip[16] = {0};
		//getlocalip(ip);
		getLocalIP(ip);
		struct sockaddr_in localaddr;
		memset(&localaddr, 0, sizeof(localaddr));
		localaddr.sin_family = AF_INET;
		localaddr.sin_port = htons(port);
		localaddr.sin_addr.s_addr = inet_addr(ip);
		if(bind(sock, (struct sockaddr*)&localaddr, sizeof(localaddr)) < 0)
			ERR_EXIT("bind");
	}
	return sock;
}



/*
 *	tcp_server - 启动tcp服务器
 *	@host:服务器IP地址或者服务器主机名
 *	@port:服务器端口号
 *	若成功则返回监听套接字
 */
int tcp_server(const char *host, unsigned short port)
{
	int listenfd;
	if ((listenfd = socket(PF_INET, SOCK_STREAM, 0)) < 0)
		ERR_EXIT("tcp_server");
	struct sockaddr_in servaddr;
	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	
	//绑定IP地址：

	if(host != NULL)
	{
		if(inet_aton(host, &servaddr.sin_addr) == 0)	//返回值为0说明host不是有效IP地址，可能是主机名
		{
			struct hostent	*hp;
			hp = gethostbyname(host);	//通过主机名获取本机所有IP地址
			if(hp == NULL)
				ERR_EXIT("gethostbyname");
			servaddr.sin_addr = *(struct in_addr*)hp->h_addr;	//存储主机第一个IP地址
		}
	}
	else	//host为NULL，绑定本机所有IP地址的任意一个
	{
		servaddr.sin_addr.s_addr = htonl(INADDR_ANY);	
	}
/************************************************/
	
	//绑定端口号、绑定套接字、监听套接字
	
	servaddr.sin_port = htons(port);
	int on = 1;
	if((setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (const char*)&on, sizeof(on))) < 0)
		ERR_EXIT("gethostbyname");
	
	if(bind(listenfd, (struct sockaddr*)&servaddr, 	sizeof(servaddr)) < 0)
		ERR_EXIT("bind");
	if(listen(listenfd, SOMAXCONN) < 0)	
		ERR_EXIT("listen");
/************************************************/

	return listenfd;
}



int getlocalip(char *ip)
{
	char host[100] = {0};
	if (gethostname(host , sizeof(host)) < 0)
		return -1;
	struct hostent *hp;
	if ((hp = gethostbyname(host)) == NULL)
		return -1;
	
	strcpy(ip , inet_ntoa(*(struct in_addr*)hp->h_addr));
	return 0;
}



void getLocalIP(char *ip){
	int inet_sock;
	struct ifreq ifr;
    
	inet_sock = socket(AF_INET, SOCK_DGRAM, 0);
	strcpy(ifr.ifr_name, "wlp3s0");
	ioctl(inet_sock, SIOCGIFADDR, &ifr);
	strcpy(ip, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
}





/*
 *activate_nonblock - 设置I/O为非阻塞模式
 *@fd: 文件描述符
 */
void activate_nonblock(int fd)
{
	int ret;
	int flags = fcntl(fd,F_GETFL);
	if(flags == -1)
		ERR_EXIT("fcntl");
	
	flags |=O_NONBLOCK;
	ret = fcntl(fd, F_SETFL, flags);
	if(ret == -1)
		ERR_EXIT("fcntl");
}

/*
 *deactivate_nonblock - 设置I/O为阻塞模式
 *@fd: 文件描述符
 */
void deactivate_nonblock(int fd)
{
	int ret;
	int flags = fcntl(fd,F_GETFL);
	if(flags == -1)
		ERR_EXIT("fcntl");
	
	flags &=~O_NONBLOCK;
	ret = fcntl(fd, F_SETFL, flags);
	if(ret == -1)
		ERR_EXIT("fcntl");

}


/*
 *read_timeout - 读超时检测函数，不含读操作
 *@fd: 文件描述符
 *@wait_seconds: 等待超时秒数，如果为0表示不检测超时
 *成功（未超时）返回0,失败返回-1,超时返回-1并且errno = ETIMEDOUT
 */
int read_timeout(int fd , unsigned int wait_seconds)
{
	int	ret = 0;
	if(wait_seconds > 0)
	{
		fd_set	read_fdset;
		struct timeval	timeout;

		FD_ZERO(&read_fdset);	//清空文件集合
		FD_SET(fd,&read_fdset);	//将fd加入文件集合

		timeout.tv_sec = wait_seconds;	//设置超时时间
		timeout.tv_usec = 0;
		do
		{
			ret = select(fd+1,&read_fdset,NULL,NULL,&timeout);	//用select函数判断fd规定时间内是否有数据可读
		}while(ret < 0 && errno == EINTR);	//若select函数调用失败且是因为有信号中断，重启select函数，继续循环

		if(ret == 0)	//ret为0表示select中fd超时
		{
			ret = -1;
			errno = ETIMEDOUT;
		}
		else if(ret == 1)	//ret为1表示select中fd未超时有数据可读
			ret = 0;
	}

	return ret;
}



/*
 *write_timeout - 写超时检测函数，不含写操作
 *@fd: 文件描述符
 *@wait_seconds: 等待超时秒数，如果为0表示不检测超时
 *成功（未超时）返回0,失败返回-1,超时返回-1并且errno = ETIMEDOUT
 */
int write_timeout(int fd , unsigned int wait_seconds)
{
	int	ret = 0;
	if(wait_seconds > 0)
	{
		fd_set	write_fdset;
		struct timeval	timeout;

		FD_ZERO(&write_fdset);	//清空文件集合
		FD_SET(fd,&write_fdset);	//将fd加入文件集合

		timeout.tv_sec = wait_seconds;	//设置超时时间
		timeout.tv_usec = 0;
		do
		{
			ret = select(fd+1,NULL,&write_fdset,NULL,&timeout);	//用select函数判断fd规定时间内是否可写数据
		}while(ret < 0 && errno == EINTR);	//若select函数调用失败且是因为有信号中断，重启select函数，继续循环

		if(ret == 0)	//ret为0表示select中fd超时
		{
			ret = -1;
			errno = ETIMEDOUT;
		}
		else if(ret == 1)	//ret为1表示select中fd未超时且可写数据
			ret = 0;
	}

	return ret;
}


/*
 *accept_timeout - 带超时的accept  包含accept操作
 *@fd: 套接字
 *@addr: 输出参数，返回对方地址
 *@wait_seconds: 等待超时秒数，如果为0表示正常模式
 *成功（未超时）返回已连接套接字，失败返回-1,超时返回-1并且errno = ETIMEDOUT
 */
int accept_timeout(int fd, struct sockaddr_in *addr, unsigned int wait_seconds)
{
	int	ret;
	socklen_t	addrlen = sizeof(struct sockaddr_in);

	if(wait_seconds > 0)	//判断超时
	{
		fd_set	accept_fdset;
		struct timeval	timeout;
		FD_ZERO(&accept_fdset);
		FD_SET(fd,&accept_fdset);
		timeout.tv_sec = wait_seconds;
		timeout.tv_usec = 0;
		
		do
		{
			ret = select(fd+1,&accept_fdset,NULL,NULL,&timeout);
		}while(ret < 0 && errno == EINTR);

		if(ret == -1)	//select函数出错
			return -1;
		else if(ret == 0)	//fd读取超时
		{
			errno = ETIMEDOUT;
			return -1;
		}
	}

	if(addr != NULL)
		ret = accept(fd,(struct sockaddr*)addr,&addrlen);
	else
		ret = accept(fd,NULL,NULL);

	if(ret == -1)
		ERR_EXIT("accept");

	return ret;
}





/*
 *connect_timeout - 带超时的connect，包含connect操作
 *@fd: 套接字
 *@addr: 要连接的对方地址
 *@wait_seconds: 等待超时秒数，如果为0表示正常模式
 *成功（未超时）返回0,失败返回-1,超时返回-1并且errno = ETIMEDOUT
 */
int connect_timeout(int fd, struct sockaddr_in *addr, unsigned int wait_seconds)
{
	int ret;
	socklen_t	addrlen = sizeof(struct sockaddr_in);

	if(wait_seconds > 0)
		activate_nonblock(fd);
	
	ret = connect(fd, (struct sockaddr*)addr, addrlen);
	//若ret < 0 && errno != EINPROGRESS，代表函数调用错误，直接返回-1
	if(ret < 0 && errno == EINPROGRESS)	//若满足条件，代表connect返回失败,连接正在处理中
	{
		fd_set	connect_fdset;
		struct timeval	timeout;
		FD_ZERO(&connect_fdset);
		FD_SET(fd,&connect_fdset);
		timeout.tv_sec = wait_seconds;
		timeout.tv_usec = 0;
		
		do
		{	//一旦连接建立，套接字就可写
			ret = select(fd+1,NULL,&connect_fdset,NULL,&timeout);
		}while(ret < 0 && errno == EINTR);
		
		if(ret == 0)	//时间到了还没有可写事件，代表连接超时
		{
			ret = -1;
			errno = ETIMEDOUT;
		}
		else if(ret < 0)
			return -1;
		else if(ret == 1)
		{
			/*ret返回为1，可能有两种情况，一种是连接建立成功，一种是套接字产生错误*/
			/*此时错误信息不会保存至errno变量中，因此，需要调用getsockopt来获取*/
			int err;
			socklen_t socklen = sizeof(err);
			int sockoptret = getsockopt(fd,SOL_SOCKET,SO_ERROR,&err,&socklen);
			if(sockoptret == -1)
				return -1;
			if(err == 0)	//套接字没有错误
				ret = 0;
			else
			{
				errno = err;	//套接字错误代码
				ret = -1;
			}
		}
	}
	
	if(wait_seconds > 0)
		deactivate_nonblock(fd);

	return ret;
}








ssize_t 	readn(int fd,void *buf,size_t count)
{
	size_t	nleft=count;	//剩余要读取的字节数
	ssize_t	nread;		//每次接收到的字节数
	char 	*bufp=(char*)buf;

	while(nleft>0)
	{
		if((nread=read(fd,bufp,nleft))<0)
		{
			if(errno == EINTR)
				continue;
			return -1;	//读取失败
		}
		else if(nread==0)
			return count-nleft;
		bufp+=nread;
		nleft-=nread;

	} 
	return 	count;
}


ssize_t	writen(int fd,const void *buf,size_t count)
{
	size_t	nleft=count;	//剩余要发送的字节数
	ssize_t	nwritten;	//每次发送的字节数
	char 	*bufp=(char*)buf;

	printf("writen begin\n");
	while(nleft>0)
	{
		printf("aaaaaaaa %d\n", fd);
		
		if((nwritten=write(fd,bufp,nleft))<0)
		{
			if(errno == EINTR)
				continue;
			printf("write fail   errno:%d\n", errno);
			return -1;	//写入失败
		}
		else if(nwritten==0)
			continue;
		bufp+=nwritten;
		nleft-=nwritten;

	} 
	printf("writen end\n");
	return 	count;
}



ssize_t	recv_peek(int sockfd,void *buf,size_t len)
{
	while(1)
	{
		int 	ret=recv(sockfd,buf,len,MSG_PEEK);
		if(ret == -1 && errno == EINTR)
			continue;
		return ret;
	}
}

ssize_t readline(int sockfd,void *buf,size_t maxline)
{
	int 	ret;
	int		nread;
	char*	bufp=(char*)buf;
	int 	nleft=maxline;

	while(1)
	{
		ret=recv_peek(sockfd,bufp,nleft);
		if(ret<0)
			return ret;
		else if(ret==0)
			return ret;

		nread=ret;	//接收到的字节数
		int 	i;
		for(i=0;i<nread;++i)
		{
			if(bufp[i]=='\n')
			{
				ret=readn(sockfd,bufp,i+1); 
				if(ret!=i+1)
					exit(EXIT_FAILURE);

				return ret;
			}
		}
		if(nread>nleft)	//判断接收的字节数是否大于剩余能放的字节数
			exit(EXIT_FAILURE);
		nleft-=nread;	//剩余能放字节数减去接收的字节数 
		ret=readn(sockfd,bufp,nread);	//按接收的字节数读取接收的字符
		if(ret != nread)
			exit(EXIT_FAILURE);

		bufp+=nread;
	}
	return -1;
}




void send_fd(int sock_fd, int fd )
{
	int ret;
	struct msghdr	msg;
	char sendchar = 0;
	struct iovec	vec;
	char cmsgbuf[CMSG_SPACE(sizeof(fd))];
	struct cmsghdr	*p_cmsg;
	int *p_fds;
	msg.msg_control = cmsgbuf;	//辅助数据的地址
	msg.msg_controllen = sizeof(cmsgbuf);	//辅助数据的长度
	p_cmsg = CMSG_FIRSTHDR(&msg);	//返回指向附属数据缓冲区内的第一个附属对象的 struct cmsghdr 指针
	p_cmsg->cmsg_level = SOL_SOCKET;	//原始的协议级别
	p_cmsg->cmsg_type = SCM_RIGHTS;		//控制信息类型：文件描述符
	p_cmsg->cmsg_len = CMSG_LEN(sizeof(fd));	//附属数据字节
	p_fds = (int*)CMSG_DATA(p_cmsg);	//返回跟随在头部以及填充字节之后的附属数据的第一个字节的地址
	*p_fds = fd;
	
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = &vec;
	msg.msg_iovlen = 1;
	msg.msg_flags = 0;
	
	vec.iov_base = &sendchar;
	vec.iov_len = sizeof(sendchar);
	ret = sendmsg(sock_fd, &msg, 0);
	if(ret != 1)
		ERR_EXIT("sendmsg");
}

int recv_fd(const int sock_fd)
{
	int ret;
	struct msghdr	msg;
	char recvchar;
	struct iovec	vec;
	int recv_fd;
	char cmsgbuf[CMSG_SPACE(sizeof(recv_fd))];
	struct cmsghdr	*p_cmsg;
	int *p_fd;
	vec.iov_base = &recvchar;
	vec.iov_len = sizeof(recvchar);
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = &vec;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);
	msg.msg_flags = 0;

	p_fd = (int*)CMSG_DATA(CMSG_FIRSTHDR(&msg));
	*p_fd = -1;
	ret = recvmsg(sock_fd , &msg , 0);
	if(ret != 1)
		ERR_EXIT("recvmsg");
	
	p_cmsg = CMSG_FIRSTHDR(&msg);
	if(p_cmsg == NULL)
		ERR_EXIT("no passed fd");

	p_fd = (int*)CMSG_DATA(p_cmsg);
	recv_fd = *p_fd;
	if(recv_fd == -1)
		ERR_EXIT("no passed fd");

	return recv_fd;
}



const char * statbuf_get_perms(struct stat *sbuf)
{
		//权限获取
		static char perms[] = "----------";
		perms[0] = '?';
		
		mode_t mode = sbuf->st_mode;
		switch(mode & S_IFMT)
		{
			case S_IFREG: perms[0] = '-'; break;
			case S_IFDIR: perms[0] = 'd'; break;
			case S_IFLNK: perms[0] = 'l'; break;
			case S_IFIFO: perms[0] = 'p'; break;
			case S_IFSOCK: perms[0] = 's'; break;
			case S_IFCHR: perms[0] = 'c'; break;
			case S_IFBLK: perms[0] = 'b'; break;
		}

		if(mode & S_IRUSR)
		{
			perms[1] = 'r';
		}
		if(mode & S_IWUSR)
		{
			perms[2] = 'w';
		}
		if(mode & S_IXUSR)
		{
			perms[3] = 'x';
		}
		if(mode & S_IRGRP)
		{
			perms[4] = 'r';
		}
		if(mode & S_IWGRP)
		{
			perms[5] = 'w';
		}
		if(mode & S_IXGRP)
		{
			perms[6] = 'x';
		}
		if(mode & S_IROTH)
		{
			perms[7] = 'r';
		}
		if(mode & S_IWOTH)
		{
			perms[8] = 'w';
		}
		if(mode & S_IXOTH)
		{
			perms[9] = 'x';
		}
		if(mode & S_ISUID)
		{
			perms[3] = (perms[3] == 'x') ? 's' : 'S';
		}
		if(mode & S_ISGID)
		{
			perms[6] = (perms[6] == 'x') ? 's' : 'S';
		}
		if(mode & S_ISVTX)
		{
			perms[9] = (perms[9] == 'x') ? 't' : 'T';
		}

		return perms;
}


const char * statbuf_get_date(struct stat *sbuf)
{
		static char datebuf[64] = {0};
		const char *p_date_format = "%b %e %H:%M";
		struct timeval tv;
		gettimeofday(&tv, NULL);
		time_t local_time = tv.tv_sec;
		if(sbuf->st_mtime > local_time || (local_time - sbuf->st_mtime) > 60*60*24*182)	//文件时间比当前系统时间大
		{
			p_date_format = "%b %e  %Y";
		}

		struct tm *p_tm = localtime(&local_time);
		strftime(datebuf, sizeof(datebuf), p_date_format, p_tm);

		return datebuf;
}


static int lock_internal(int fd, int lock_type)
{
	int ret;
	struct flock the_lock;
	memset(&the_lock, 0,sizeof(the_lock));
	the_lock.l_type = lock_type;
	the_lock.l_whence = SEEK_SET;
	the_lock.l_start = 0;
	the_lock.l_len = 0;
	
	do{
		ret = fcntl(fd, F_SETLKW, &the_lock);
	}while(ret < 0 && errno == EINTR);	//若因信号中断而失败，继续加锁	
	
	return ret;
}

int lock_file_read(int fd)
{
	return lock_internal(fd, F_RDLCK);
}

int lock_file_write(int fd)
{
	return lock_internal(fd, F_WRLCK);
}

int unlock_file(int fd)
{
	int ret;
	struct flock the_lock;
	memset(&the_lock, 0,sizeof(the_lock));
	the_lock.l_type = F_UNLCK;
	the_lock.l_whence = SEEK_SET;
	the_lock.l_start = 0;
	the_lock.l_len = 0;
	
	
	ret = fcntl(fd, F_SETLK, &the_lock);	//非阻塞解锁
	
	return ret;
}


static struct timeval s_curr_time;
long get_time_sec(void)
{
	if(gettimeofday(&s_curr_time, NULL) < 0)
	{
		ERR_EXIT("gettimeofday");
	}
	return s_curr_time.tv_sec;
}

long get_time_usec(void)
{
	return s_curr_time.tv_usec;
}

void nano_sleep(double seconds)
{
	time_t secs = (time_t)seconds;				//整数部分
	double fractional = seconds - (double)secs;	//小数部分

	struct timespec ts;
	ts.tv_sec = secs;
	ts.tv_nsec = (long)(fractional * (double)1000000000);

	int ret;
	do{
		ret = nanosleep(&ts, &ts);
	}while(ret == -1 && errno == EINTR);	//如果被信号中断，继续睡眠
}
