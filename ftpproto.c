#include "ftpproto.h"
#include "sysutil.h"
#include "str.h"
#include "ftpcodes.h"
#include "common.h"
#include "tunable.h"
#include "privsock.h"




void ftp_reply(session_t *sess, int status, const char *text);
void ftp_lreply(session_t *sess, int status, const char *text);


int list_common(session_t *sess, int detail);
void limit_rate(session_t *sess, int bytes_transfered, int is_upload);
void upload_common(session_t *sess, int is_append);

int get_port_fd(session_t *sess);
int get_pasv_fd(session_t *sess);
int get_transfer_fd(session_t *);
int port_active(session_t *);
int pasv_active(session_t *);

static void do_user(session_t *sess);
static void do_pass(session_t *sess);

static void do_cwd(session_t *sess);
static void do_cdup(session_t *sess);
static void do_quit(session_t *sess);
static void do_port(session_t *sess);
static void do_pasv(session_t *sess);
static void do_type(session_t *sess);
static void do_stru(session_t *sess);
static void do_mode(session_t *sess);
static void do_retr(session_t *sess);
static void do_stor(session_t *sess);
static void do_appe(session_t *sess);
static void do_list(session_t *sess);
static void do_nlst(session_t *sess);
static void do_rest(session_t *sess);
static void do_abor(session_t *sess);
static void do_pwd(session_t *sess);
static void do_mkd(session_t *sess);
static void do_rmd(session_t *sess);
static void do_dele(session_t *sess);
static void do_rnfr(session_t *sess);
static void do_rnto(session_t *sess);
static void do_site(session_t *sess);
static void do_syst(session_t *sess);
static void do_feat(session_t *sess);
static void do_size(session_t *sess);
static void do_stat(session_t *sess);
static void do_noop(session_t *sess);
static void do_help(session_t *sess);


typedef struct ftpcmd{
	const char *cmd;
	void(*cmd_handler)(session_t *);
} ftpcmd_t;

static ftpcmd_t ctrl_cmds[] = {
	/* 访问控制命令 */
	{"USER", do_user},
	{"PASS", do_pass},
	{"CWD", do_cwd},
	{"XCWD", do_cwd},
	{"CDUP", do_cdup},
	{"XCUP", do_cdup},
	{"QUIT", do_quit},
	{"ACCT", NULL},
	{"SMNT", NULL},
	{"REIN", NULL},
	/* 传输参数命令 */
	{"PORT", do_port},
	{"PASV", do_pasv},
	{"TYPE", do_type},
	{"STRU", do_stru},
	{"MODE", do_mode},

	/* 服务命令 */
	{"RETR", do_retr},
	{"STOR", do_stor},
	{"APPE", do_appe},
	{"LIST", do_list},
	{"NLST", do_nlst},
	{"REST", do_rest},
	{"ABOR", do_abor},
	{"\377\364\377\362ABOR", do_abor},
	{"PWD", do_pwd},
	{"XPWD", do_pwd},
	{"MKD", do_mkd},
	{"XMKD", do_mkd},
	{"RMD", do_rmd},
	{"XRMD", do_rmd},
	{"DELE", do_dele},
	{"RNFR", do_rnfr},
	{"RNTO", do_rnto},
	{"SITE", do_site},
	{"SYST", do_syst},
	{"FEAT", do_feat},
	{"SIZE", do_size},
	{"STAT", do_stat},
	{"NOOP", do_noop},
	{"HELP", do_help},
	{"STOU", NULL},
	{"ALLO", NULL}
};



void handle_child(session_t *sess)
{
	ftp_reply(sess, FTP_GREET, "(miniftpd 0.1)");	//连接成功发送给客户端信息
	int ret;

	
	sess->port_addr = NULL;
	while(1)
	{

		memset(sess->cmdline, 0, sizeof(sess->cmdline));
		memset(sess->cmd, 0, sizeof(sess->cmd));
		memset(sess->arg, 0, sizeof(sess->arg));
		ret = readline(sess->ctrl_fd, sess->cmdline, MAX_COMMAND_LINE);	//接收客户端命令行
		if(ret == -1)
			ERR_EXIT("readline");
		else if(ret == 0)
			exit(EXIT_SUCCESS);

		//去除\r\n
		str_trim_crlf(sess->cmdline);
		printf("cmdline=[%s]\n",sess->cmdline);
		//解析FTP命令与参数
		str_split(sess->cmdline, sess->cmd, sess->arg, ' ');
		printf("cmd=[%s] arg=[%s]\n", sess->cmd, sess->arg);
		//将命令转换成大写
		str_upper(sess->cmd);
		//处理FTP命令
		
		/*
		if(strcmp("USER", sess->cmd) == 0)
		{
			do_user(sess);
		}
		else if(strcmp("PASS", sess->cmd) == 0)
		{
			do_pass(sess);
		}

		*/

		int i;
		int size = sizeof(ctrl_cmds) / sizeof(ctrl_cmds[0]) ;
		for(i = 0 ; i < size ; i++)
		{
			if(strcmp(ctrl_cmds[i].cmd, sess->cmd) == 0)
			{
				if(ctrl_cmds[i].cmd_handler != NULL)
				{
					ctrl_cmds[i].cmd_handler(sess);
				}
				else
				{
					ftp_reply(sess, FTP_COMMANDNOTIMPL, "Unimplement command.");
				}
				break;
			}	
		}

		if( i == size )
		{
			ftp_reply(sess, FTP_BADCMD, "Unknown command.");
		}

	}
}


void ftp_reply(session_t *sess, int status, const char *text)
{
	char buf[1024] = {0};
	sprintf(buf, "%d %s\r\n", status, text);
	writen(sess->ctrl_fd, buf,strlen(buf));
}


void ftp_lreply(session_t *sess, int status, const char *text)
{
	char buf[1024] = {0};
	sprintf(buf, "%d-%s\r\n", status, text);
	writen(sess->ctrl_fd, buf,strlen(buf));
}


int list_common(session_t * sess, int detail)
{
	DIR *dir = opendir(".");
	if(dir == NULL)	//目录打开失败返回0
	{
		return 0;
	}

	struct dirent *dt;
	struct stat sbuf;
	while((dt = readdir(dir)) != NULL)
	{
		if(lstat(dt->d_name, &sbuf) < 0)
		{
			continue;
		}
		if(dt->d_name[0] == '.')
			continue;


		char buf[1024] = {0};
		if(detail)
		{
			//权限获取
			const char *perms = statbuf_get_perms(&sbuf);

			int off = 0;
			off += sprintf(buf, "%s", perms);
			off += sprintf(buf + off, "%3lu %-8d %-8d ", sbuf.st_nlink, sbuf.st_uid, sbuf.st_gid);
			off += sprintf(buf + off, "%8lu ", (unsigned long)sbuf.st_size);


			//获取日期
			const char *datebuf = statbuf_get_date(&sbuf);
		
			off += sprintf(buf + off, "%s ", datebuf);
			if(S_ISLNK(sbuf.st_mode))
			{	
				char tmp[1024] = {0};
				readlink(dt->d_name, tmp, sizeof(tmp));
				off += sprintf(buf + off, "%s -> %s\r\n", dt->d_name, tmp);
			}
			else
			{
				sprintf(buf + off, "%s\r\n", dt->d_name);
			}
			
		}
		else
		{
			sprintf(buf, "%s\r\n", dt->d_name);
		}

		//printf("%s", buf);
		writen(sess->data_fd, buf, strlen(buf));

	}
	closedir(dir);

	return 1;
}
/*
void limit_rate(session_t *sess, int bytes_transfered, int is_upload)
{

	//睡眠时间 = （当前传输速度 / 最大传输速度 - 1）* 当前传输时间
	long curr_sec = get_time_sec();
	long curr_usec = get_time_usec();

	//获得当前传输时间
	double elapsed;
	elapsed = curr_sec - sess->bw_transfer_start_sec;
	elapsed += (double)(curr_usec - sess->bw_transfer_start_usec) / (double)1000000;

	//计算当前传输速度
	unsigned int bw_rate = (unsigned int)((double)bytes_transfered / elapsed);
	//计算速度比率
	double rate_ratio;
	if(is_upload)
	{
		if(bw_rate <= sess->bw_upload_rate_max)
		{
			//不需要限速
			return ;
		}

		rate_ratio = bw_rate / sess->bw_upload_rate_max;
	}
	else
	{
		if(bw_rate <= sess->bw_download_rate_max)
		{
			//不需要限速
			return ;
		}

		rate_ratio = bw_rate / sess->bw_download_rate_max;
	}

	//计算睡眠时间
	double pause_time;
	pause_time = (rate_ratio - (double)1) * elapsed;

	//睡眠
	nano_sleep(pause_time);
	
	//更新时间状态
	sess->bw_transfer_start_sec = get_time_sec();
	sess->bw_transfer_start_usec = get_time_usec();

}
*/
void upload_common(session_t *sess, int is_append)
{
	//上传文件
	//断点续载

	//创建数据连接
	if(get_transfer_fd(sess) == 0)	//返回0失败
	{
		printf("get_transfer_fd\n");
		return ;
	}

	//获取文件传输断点位置
	long long offset = sess->restart_pos;
	sess->restart_pos = 0;

	//打开文件
	int fd = open(sess->arg, O_CREAT | O_WRONLY, 0666);
	if(fd == -1)
	{
		ftp_reply(sess, FTP_UPLOADFAIL, "Could not create file.");
		return ;
	}

	
	int ret;
	//加写锁
	ret = lock_file_write(fd);
	if(ret == -1)
	{
		close(fd);
		ftp_reply(sess, FTP_UPLOADFAIL, "Could not create file.");
		return ;
	}

	/*	文件上传有3种模式：
	 *	STOR
	 *	REST+STOR	断点续传
	 *	APPE		断点续传
	 */
	if(!is_append && offset == 0)	//STOR
	{
		ftruncate(fd, 0);	//文件长度清零
		if(lseek(fd, 0, SEEK_SET) < 0)	//文件指针清零
		{
			ftp_reply(sess, FTP_UPLOADFAIL, "Could not create file.");
			return ;
		}
	}
	else if(!is_append && offset != 0)	//REST+STOR
	{
		if(lseek(fd, offset, SEEK_SET) < 0)	//偏移文件指针offset字节
		{
			ftp_reply(sess, FTP_UPLOADFAIL, "Could not create file.");
			return ;
		}
	}
	else if(is_append)				//APPE
	{
		if(lseek(fd, 0, SEEK_END) < 0)		//偏移文件指针到文件末尾
		{
			ftp_reply(sess, FTP_UPLOADFAIL, "Could not create file.");
			return ;
		}
	}


	//获取文件状态
	struct stat sbuf;
	ret = fstat(fd, &sbuf);
	if(!S_ISREG(sbuf.st_mode))
	{
		ftp_reply(sess, FTP_UPLOADFAIL, "Could not create file.");
		return ;
	}
	
	//响应150
	char text[1024] = {0};
	if(sess->is_ascii)
	{
		sprintf(text, "Opening ASCII mode data connection for %s (%lld bytes)", sess->arg, (long long)sbuf.st_size);
	}
	else
	{
		sprintf(text, "Opening BINARY mode data connection for %s (%lld bytes)", sess->arg, (long long)sbuf.st_size);
	}
	ftp_reply(sess, FTP_DATACONN, text);
	
	//上传文件

	int flag = 0;
	char buf[1024];
	//睡眠时间 = （当前传输速度 / 最大传输速度 - 1）* 当前传输时间
	//sess->bw_transfer_start_sec = get_time_sec();	//开始计时
	//sess->bw_transfer_start_usec = get_time_usec();	

	//		每传输一块就需要2次系统调用，效率不高
	while(1)
	{
		ret = read(sess->data_fd, buf, sizeof(buf));
		if(ret == -1)
		{
			if(errno == EINTR)	//被信号中断，继续传输
				continue;
			else	
			{
				flag = 2;	//读取网络文件失败
				break;
			}
		}
		else if(ret == 0)
		{
			flag = 0;		//读取文件成功
			break;
		}
		
		
		//limit_rate(sess, ret, 1);	//上传限速
		
		if(writen(fd, buf, ret) != ret)
		{
			flag = 1;		//写入本地文件失败
			break;
		}
	}



	//关闭数据套接字
	close(sess->data_fd);
	sess->data_fd = -1;
	sess->port_addr = NULL;

	if(flag == 0)	//传输成功
	{
		//响应226
		ftp_reply(sess, FTP_TRANSFEROK, "Transfer complete.");
	}
	else if(flag == 1)
	{
		//响应451
		ftp_reply(sess, FTP_BADSENDFILE, "Failure writting to local file.");
	}
	else if(flag == 2)
	{
		//响应426
		ftp_reply(sess, FTP_BADSENDNET, "Failure reading from network stream.");
	}

	close(fd);

}

int port_active(session_t *sess)
{
	printf("port_active begin\n");
	if(sess->port_addr)
	{
		printf("sess->port_addr:%s\n", inet_ntoa(sess->port_addr->sin_addr));
		if(pasv_active(sess))
		{
			fprintf(stderr, "both port an pasv are active");
			exit(EXIT_FAILURE);
		}
		printf("port_active return 1\n");
		return 1;
	}
	printf("port_active return 0\n");
	return 0;
}
int pasv_active(session_t *sess)
{
	/*
	if(sess->pasv_listen_fd != -1)
	{
		if(port_active(sess))
		{
			fprintf(stderr, "both port an pasv are active");
			exit(EXIT_FAILURE);
		}

		return 1;
	}
	*/
	printf("priv_sock_send_cmd begin\n");
	priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_PASV_ACTIVE);
	printf("priv_sock_send_cmd end\n");

	int active = priv_sock_get_int(sess->child_fd);
	if(active)
	{
		if(port_active(sess))
		{
			fprintf(stderr, "both port an pasv are active");
			exit(EXIT_FAILURE);
		}

		return 1;
	}
	return 0;
}

int get_port_fd(session_t *sess)
{
	priv_sock_send_cmd(sess->child_fd,PRIV_SOCK_GET_DATA_SOCK);	//向nobody进程发送PRIV_SOCK_GET_DATA_SOCK命令
	unsigned short port = ntohs(sess->port_addr->sin_port);
	char *ip = inet_ntoa(sess->port_addr->sin_addr);

	
	//向nobody进程发送端口
	priv_sock_send_int(sess->child_fd, (int)port);
	//向nobody进程发送IP字符串
	priv_sock_send_buf(sess->child_fd, ip, strlen(ip));

	//接收连接结果的应答
	char res = priv_sock_get_result(sess->child_fd);
	if(res == PRIV_SOCK_RESULT_BAD)	//连接失败
	{
		printf("PRIV_SOCK_RESULT_BAD\n");
		return 0;
	}
	else if(res == PRIV_SOCK_RESULT_OK)
	{
		//接收nobody进程的数据连接套接字
		sess->data_fd = priv_sock_recv_fd(sess->child_fd);
	}

	return 1;
}

int get_pasv_fd(session_t *sess)
{
	priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_PASV_ACCEPT);
	char res = priv_sock_get_result(sess->child_fd);
	if(res == PRIV_SOCK_RESULT_BAD)
	{
		return 0;
	}
	else if(res == PRIV_SOCK_RESULT_OK)
	{
		sess->data_fd = priv_sock_recv_fd(sess->child_fd);
	}

	return 1;
}


int get_transfer_fd(session_t *sess)
{
	//检测是否收到PORT或者PASV命令
	printf("get_transfer_fd  begin\n");
	if(!port_active(sess) && !pasv_active(sess))
	{
		ftp_reply(sess, FTP_BADSENDCONN, "Use PORT or PASV first.");
		return 0;
	}

	int ret = 1;	//返回值

	printf("PORT or PASV\n");
	
	//如果是主动模式
	if(port_active(sess))
	{
		//tcp_client(20);
		
		/*
		int fd = tcp_client(0);	//创建数据连接的套接字
		if(connect_timeout(fd, sess->port_addr, tunable_connect_timeout) < 0)	//带超时的连接
		{
			close(fd);
			return 0;
		}

		sess->data_fd = fd;
		*/
		

		if(get_port_fd(sess) == 0)	//数据连接创建失败
		{
			printf("get_port_fd\n");
			ret = 0;
		}

	}

	//如果是被动模式
	if(pasv_active(sess))
	{
		/*
		int fd = accept_timeout(sess->pasv_listen_fd, NULL, tunable_accept_timeout);
		close(sess->pasv_listen_fd);	//关闭监听套接字

		if(fd == -1)	//接收失败
		{
			close(sess->pasv_listen_fd);
			return 0;
		}

		sess->data_fd = fd;	//数据连接套接字
		*/
		if(get_pasv_fd(sess) == 0)
		{
			ret = 0;
		}
	}

	//释放存发数据连接地址的内存
	if(sess->port_addr)
	{
		free(sess->port_addr);
		sess->port_addr = NULL;
	}

	return ret;

}

static void do_user(session_t *sess)
{
	struct passwd *pw = getpwnam(sess->arg);
	if(pw == NULL)
	{
		//用户不存在
		ftp_reply(sess, FTP_LOGINERR, "1Login incorrect");
		return ;
	}

	sess->uid = pw->pw_uid;
	ftp_reply(sess, FTP_GIVEPWORD, "Please specify the password.");

	if(sess->port_addr)
		printf("do_user\n");
}

static void do_pass(session_t *sess)
{
	//PASSWORD
	struct passwd *pw = getpwuid(sess->uid);
	if(pw == NULL)
	{
		//用户不存在
		ftp_reply(sess, FTP_LOGINERR, "2Login incorrect");
		return ;
	}

	struct spwd *sp = getspnam(pw->pw_name);
	if(sp == NULL)
	{
		//用户不存在
		ftp_reply(sess, FTP_LOGINERR, "3Login incorrect");
		return ;
	}
	
	//将明文进行加密
	char * encrypted_pass = crypt(sess->arg, sp->sp_pwdp);
	//验证密码
	if(strcmp(encrypted_pass, sp->sp_pwdp) != 0)
	{
		ftp_reply(sess, FTP_LOGINERR, "4Login incorrect.");
		return ;
	}
	

	//进程用户切换回登录用户
	umask(tunable_local_umask);
	setegid(pw->pw_gid);
	seteuid(pw->pw_uid);
	chdir(pw->pw_dir);

	ftp_reply(sess, FTP_LOGINOK, "Login successful.");

}





static void do_cwd(session_t *sess)	//改变当前路径
{
	if(chdir(sess->arg) < 0)
	{
		ftp_reply(sess, FTP_FILEFAIL, "Failed to chang directory.");
		return ;
	}
	ftp_reply(sess, FTP_CWDOK, "Directory successfully changed.");

}
static void do_cdup(session_t *sess)
{
	if(chdir("..") < 0)
	{
		ftp_reply(sess, FTP_FILEFAIL, "Failed to chang directory.");
		return ;
	}
	ftp_reply(sess, FTP_CWDOK, "Directory successfully changed.");
}
static void do_quit(session_t *sess){}
static void do_port(session_t *sess)
{
	unsigned int v[6];

	sscanf(sess->arg, "%u,%u,%u,%u,%u,%u", &v[2], &v[3], &v[4], &v[5], &v[0], &v[1]);
	sess->port_addr = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
	memset(sess->port_addr, 0, sizeof(struct sockaddr_in));
	sess->port_addr->sin_family = AF_INET;
	unsigned char *p = (unsigned char *)&sess->port_addr->sin_port;	//得到套接字端口
	p[0] = v[0];
	p[1] = v[1];	

	p = (unsigned char *)&sess->port_addr->sin_addr;	//得到套接字IP地址
	p[0] = v[2];
	p[1] = v[3];
	p[2] = v[4];
	p[3] = v[5];

	ftp_reply(sess, FTP_PORTOK, "PORT command successful.Consider using PASV");
}
static void do_pasv(session_t *sess)
{
	
	char ip[16] = {0};
	//getlocalip(ip);
	getLocalIP(ip);
	printf("%s\n", ip);

	/*
	sess->pasv_listen_fd = tcp_server(ip, 0);	//创建被动模式监听套接字
	struct sockaddr_in addr;
	socklen_t addrlen = sizeof(addr);
	if(getsockname(sess->pasv_listen_fd, (struct sockaddr *)&addr, &addrlen) < 0)
	{
		ERR_EXIT("getsockname");
	}

	unsigned short port = ntohs(addr.sin_port);
	*/
	printf("before\n");
	priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_PASV_LISTEN);
	printf("after\n");
	unsigned short port = (unsigned short)priv_sock_get_int(sess->child_fd);

	unsigned int v[4];
	sscanf(ip, "%u.%u.%u.%u", &v[0], &v[1], &v[2], &v[3]);

	char text[1024] = {0};
	sprintf(text, "Entering Passive Mode (%u,%u,%u,%u,%u,%u).",
		v[0], v[1], v[2], v[3], port>>8, port&0xFF);

	ftp_reply(sess, FTP_PASVOK, text);
}
static void do_type(session_t *sess)
{
	if(strcmp(sess->arg, "A") == 0)
	{
		sess->is_ascii = 1;
		ftp_reply(sess, FTP_TYPEOK, "Switching to ASCII mode.");
	}
	else if(strcmp(sess->arg, "I") == 0)
	{
		sess->is_ascii = 0;
		ftp_reply(sess, FTP_TYPEOK, "Switching to Binary mode.");
	}
	else
	{
		ftp_reply(sess, FTP_BADCMD, "Unrecognised TYPE command.");
	}
}
static void do_stru(session_t *sess){}
static void do_mode(session_t *sess){}
static void do_retr(session_t *sess)
{
	//下载文件
	//断点续载

	//创建数据连接
	if(get_transfer_fd(sess) == 0)	//返回0失败
	{
		printf("get_transfer_fd\n");
		return ;
	}

	//获取文件传输断点位置
	long long offset = sess->restart_pos;
	sess->restart_pos = 0;

	//打开文件
	int fd = open(sess->arg, O_RDONLY);
	if(fd == -1)
	{
		ftp_reply(sess, FTP_FILEFAIL, "Failed to open file.");
		return ;
	}

	
	int ret;
	//加读锁
	ret = lock_file_read(fd);
	if(ret == -1)
	{
		close(fd);
		ftp_reply(sess, FTP_FILEFAIL, "Failed to open file.");
		return ;
	}

	//判断是否是普通文件
	struct stat sbuf;
	ret = fstat(fd, &sbuf);	//保存文件状态
	if(!S_ISREG(sbuf.st_mode))
	{
		close(fd);
		ftp_reply(sess, FTP_FILEFAIL, "Failed to open file.");
		return ;
	}

	//判断断点位置是否为0
	if(offset != 0)
	{
		ret = lseek(fd, offset, SEEK_SET);	//调正文件指针
		if(ret == -1)
		{
			ftp_reply(sess, FTP_FILEFAIL, "Failed to lseek file.");
			return ;
		}
	}
	
	//响应150
	char text[1024] = {0};
	if(sess->is_ascii)
	{
		sprintf(text, "Opening ASCII mode data connection for %s (%lld bytes)", sess->arg, (long long)sbuf.st_size);
	}
	else
	{
		sprintf(text, "Opening BINARY mode data connection for %s (%lld bytes)", sess->arg, (long long)sbuf.st_size);
	}
	ftp_reply(sess, FTP_DATACONN, text);
	
	//下载文件

	/*		每传输一块就需要2次系统调用，效率不高
	int flag = 0;
	char buf[4096];
	while(1)
	{
		ret = read(fd, buf, sizeof(buf));
		if(ret == -1)
		{
			if(errno == EINTR)	//被信号中断，继续传输
				continue;
			else	
			{
				flag = 1;	//读取文件失败
				break;
			}
		}
		else if(ret == 0)
		{
			flag = 0;		//读取文件成功
			break;
		}
		
		if(writen(sess->data_fd, buf, ret) != ret)
		{
			flag = 2;		//传送文件失败
			break;
		}
	}
	*/
	
	int flag = 0;
	long long bytes_to_send = sbuf.st_size;	//文件大小
	if(offset > bytes_to_send)
	{
		bytes_to_send = 0;
	}
	else
	{
		bytes_to_send -= offset;	//除去断点位置的大小
	}
	while(bytes_to_send)
	{
		int num_this_time = (bytes_to_send > 4096 ? 4096 : bytes_to_send);
		ret = sendfile(sess->data_fd, fd, NULL, num_this_time);	//不将数据拷贝到用户空间缓冲区，直接在内核空间发送
		if(ret == -1)
		{
			flag = 2;
			break;
		}

		bytes_to_send -= ret;
	}
	
	if(bytes_to_send == 0)	//发送完毕
	{
		flag = 0;
	}



	//关闭数据套接字
	close(sess->data_fd);
	sess->data_fd = -1;
	sess->port_addr = NULL;

	if(flag == 0)	//传输成功
	{
		//响应226
		ftp_reply(sess, FTP_TRANSFEROK, "Transfer complete.");
	}
	else if(flag == 1)
	{
		//响应451
		ftp_reply(sess, FTP_BADSENDFILE, "Failure reading from local file.");
	}
	else if(flag == 2)
	{
		//响应426
		ftp_reply(sess, FTP_BADSENDNET, "Failure writting to network stream.");
	}


	close(fd);
}
static void do_stor(session_t *sess)
{
	upload_common(sess, 0);
}
static void do_appe(session_t *sess)
{
	upload_common(sess, 1);
}
static void do_list(session_t *sess)
{
	//创建数据连接
	if(get_transfer_fd(sess) == 0)	//返回0失败
	{
		printf("get_transfer_fd\n");
		return ;
	}
	//响应150
	ftp_reply(sess, FTP_DATACONN, "Here comes the directory listing.");
	
	//传输列表（详细）
	list_common(sess, 1);
	
	//关闭数据套接字
	close(sess->data_fd);
	sess->data_fd = -1;
	sess->port_addr = NULL;
	
	//响应226
	ftp_reply(sess, FTP_TRANSFEROK, "Directory send OK.");
	

}
static void do_nlst(session_t *sess)
{
	//创建数据连接
	if(get_transfer_fd(sess) == 0)	//返回0失败
	{
		printf("get_transfer_fd\n");
		return ;
	}
	//响应150
	ftp_reply(sess, FTP_DATACONN, "Here comes the directory listing.");
	
	//传输列表（简要）
	list_common(sess, 0);
	
	//关闭数据套接字
	close(sess->data_fd);
	sess->data_fd = -1;
	sess->port_addr = NULL;
	
	//响应226
	ftp_reply(sess, FTP_TRANSFEROK, "Directory send OK.");
	
}
static void do_rest(session_t *sess)
{
	sess->restart_pos = str_to_longlong(sess->arg);
	char text[1024] = {0};
	sprintf(text, "Restart position accepted (%lld).", sess->restart_pos);
	ftp_reply(sess, FTP_RESTOK, text);
}
static void do_abor(session_t *sess){}
static void do_pwd(session_t *sess)
{
	char text[1024] = {0};
	char dir[1024+1] = {0};
	getcwd(dir, 1024);
	sprintf(text, "\"%s\"", dir);

	ftp_reply(sess, FTP_PWDOK, text);
}
static void do_mkd(session_t *sess)
{
	//0777 & umask
	if(mkdir(sess->arg, 0777) < 0)
	{
		ftp_reply(sess, FTP_FILEFAIL, "Create directory operation failed.");
		return ;
	}
	char text[4096] = {0};

	if(sess->arg[0] == '/')	//判断参数是否为绝对路径
	{
		sprintf(text, "%s created", sess->arg);
	}
	else
	{
		char dir[4096+1] = {0};
		getcwd(dir, 4096);
		if(dir[strlen(dir) - 1] == '/')	//判断目录是否有'/'
		{
			sprintf(text, "%s%s created", dir, sess->arg);
		}
		else
		{
			sprintf(text, "%s/%s created", dir, sess->arg);
		}
	}
	ftp_reply(sess, FTP_MKDIROK, text);
	
}
static void do_rmd(session_t *sess)
{
	if(rmdir(sess->arg) < 0)
	{
		ftp_reply(sess, FTP_FILEFAIL, "Remove directory operation failed.");
		return ;
	}
	ftp_reply(sess, FTP_RMDIROK, "Remove directory operation successful.");

}
static void do_dele(session_t *sess)
{
	if(unlink(sess->arg) < 0)	//删除文件
	{
		ftp_reply(sess, FTP_FILEFAIL, "Delete operation failed.");
		return ;
	}
	ftp_reply(sess, FTP_DELEOK, "Delete operation successful.");
}
static void do_rnfr(session_t *sess)
{
	sess->rnfr_name = (char *)malloc(strlen(sess->arg)+1);
	memset(sess->rnfr_name, 0, strlen(sess->arg)+1);
	strcpy(sess->rnfr_name, sess->arg);

	ftp_reply(sess, FTP_RNFROK, "Ready for RNTO.");
}
static void do_rnto(session_t *sess)
{
	if(sess->rnfr_name == NULL)
	{
		ftp_reply(sess, FTP_NEEDRNFR, "RNFR required first.");
		return ;
	}

	rename(sess->rnfr_name, sess->arg);

	ftp_reply(sess, FTP_RENAMEOK, "Rename successful.");
	sess->rnfr_name = NULL;
}
static void do_site(session_t *sess){}
static void do_syst(session_t *sess)
{
	ftp_reply(sess, FTP_SYSTOK, "UNIX Type: L8");
}
static void do_feat(session_t *sess)
{
	ftp_lreply(sess, FTP_FEAT, "Features:");
	writen(sess->ctrl_fd, " EPRT\r\n", strlen(" EPRT\r\n"));
	writen(sess->ctrl_fd, " EPSV\r\n", strlen(" EPSV\r\n"));
	writen(sess->ctrl_fd, " MDTM\r\n", strlen(" MDTM\r\n"));
	writen(sess->ctrl_fd, " PASV\r\n", strlen(" PASV\r\n"));
	writen(sess->ctrl_fd, " REST STREAM\r\n", strlen(" REST STREAM\r\n"));
	writen(sess->ctrl_fd, " SIZE\r\n", strlen(" SIZE\r\n"));
	writen(sess->ctrl_fd, " TVFS\r\n", strlen(" TVFS\r\n"));
	writen(sess->ctrl_fd, " UTF8\r\n", strlen(" UTF8\r\n"));
	ftp_reply(sess, FTP_FEAT, "End");
}
static void do_size(session_t *sess)
{
	struct stat buf;
	if(stat(sess->arg, &buf) < 0)
	{
		ftp_reply(sess, FTP_FILEFAIL, "SIZE operation failed.");
		return ;
	}

	if(!S_ISREG(buf.st_mode))
	{
		ftp_reply(sess, FTP_FILEFAIL, "Could not get file size.");
		return ;
	}
	
	char text[1024] = {0};
	sprintf(text, "%lld", (long long)buf.st_size);
	ftp_reply(sess, FTP_SIZEOK, text);
}
static void do_stat(session_t *sess){}
static void do_noop(session_t *sess){}
static void do_help(session_t *sess){}
