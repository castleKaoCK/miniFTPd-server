#include "common.h"
#include "sysutil.h"
#include "session.h"
#include "str.h"
#include "tunable.h"
#include "parseconf.h"
#include "ftpproto.h"
#include "ftpcodes.h"



void pipe_handler()
{
	printf("pipe\n");
}

extern session_t *p_sess;
static unsigned int s_children;

void check_limits(session_t *sess);

void handle_sigchld(int sig);

int main(void)
{
/*
	list_common();

	char *str1 = "	a b";
	char *str2 = "             ";
	if(str_all_space(str1))
		printf("str1 all space\n");
	else
		printf("str1 not all space\n");
	if(str_all_space(str2))
		printf("str2 all space\n");
	else
		printf("str2 not all space\n");

	char str3[] = "abcdef";
	str_upper(str3);
	printf("str3 = %s\n",str3);

	long long result = str_to_longlong("12345678901234");
	printf("result = %lld\n",result);

	int n = str_octal_to_uint("711");
	printf("n=%d\n",n);
*/
	parseconf_load_file(MINIFTP_CONF);
	printf("tunable_pasv_enable=%d\n", tunable_pasv_enable);
	printf("tunable_port_enable=%d\n", tunable_port_enable);
	printf("tunable_listen_port=%u\n", tunable_listen_port);
	printf("tunable_max_clients=%u\n", tunable_max_clients);
	printf("tunable_max_per_ip=%u\n", tunable_max_per_ip);
	printf("tunable_accept_timeout=%u\n", tunable_accept_timeout);
	printf("tunable_connect_timeout=%u\n", tunable_connect_timeout);
	printf("tunable_idle_session_timeout=%u\n", tunable_idle_session_timeout);
	printf("tunable_data_connection_timeout=%u\n", tunable_data_connection_timeout);
	printf("tunable_local_umask=0%o\n", tunable_local_umask);
	printf("tunable_upload_max_rate=%u\n", tunable_upload_max_rate);
	printf("tunable_download_max_rate=%u\n", tunable_download_max_rate);
	if(tunable_listen_address == NULL)
		printf("tunable_listen_address = NULL\n");
	else
		printf("tunable_listen_address = %s\n", tunable_listen_address);
	



	if(getuid() != 0){	//root用户才能运行
		fprintf(stderr , "miniftpd: must be started as root\n");
		exit(EXIT_FAILURE);
	}


	session_t	sess = 
	{
		/*控制连接*/
		0, -1, "", "", "",
		/*数据连接*/
		NULL, -1, -1, 0,
		/*限速*/
		0, 0, 0, 0,
		/*父子进程通道*/
		-1, -1,
		/*FTP协议状态*/
		0, 0, NULL, 0,
		/*连接数限制*/
		0
	};

	p_sess = &sess;

	sess.bw_upload_rate_max = tunable_upload_max_rate;
	sess.bw_download_rate_max = tunable_download_max_rate;

	signal(SIGCHLD, handle_sigchld);	//忽略子进程结束信号
	signal(SIGPIPE, pipe_handler);

	int listenfd = tcp_server(NULL, 5188);	//封装功能，直接返回监听套接字
	int conn;
	pid_t pid;

	/*
	 *	等待用户连接,对每个客户端创建一个进程
	 *	父进程循环等待TCP连接
	 *	子进程开启新会话为客户端服务
	 */
	while(1){
		conn = accept_timeout(listenfd, NULL, 0);
		if(conn == -1)
			ERR_EXIT("accept_timeout");

		
		++s_children;
		sess.num_clients = s_children;

		pid = fork();
		if(pid == -1)
		{
			--s_children;
			sess.num_clients = s_children;
			ERR_EXIT("fork");
		}

		if(pid == 0)
		{
			close(listenfd);
			sess.ctrl_fd = conn;
			
			check_limits(&sess);	//连接数判断
			signal(SIGCHLD, SIG_IGN);

			begin_session(&sess);	//开启新任务
		}
		else
			close(conn);
			
	}

	return 0;
}


void check_limits(session_t *sess)
{
	if(tunable_max_clients > 0 && sess->num_clients > tunable_max_clients)
	{
		ftp_reply(sess, FTP_TOO_MANY_USERS, "There are too many \
			connected users, please try later.");
		
		exit(EXIT_FAILURE);
	}
}


void handle_sigchld(int sig)
{
	pid_t pid;
	while((pid = waitpid(-1 , NULL, WNOHANG) > 0))	//若未等待到任何子进程，会立即返回
	{
		;
	}

	--s_children;
}
