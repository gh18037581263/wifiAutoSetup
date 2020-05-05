#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <time.h>
#include <syslog.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <errno.h>      /* for definition of errno */
#include <stdarg.h>     /* ISO C variable aruments */
#include <string.h>

void err_quit(const char *fmt, ...);
void creat_daemon(void);
pid_t get_task_pid(const char *name_str);
int create_task(const char *name_str);
int fd;

int main(){
	time_t t;

	creat_daemon();
	fd = open("daemon.log",O_WRONLY|O_CREAT|O_APPEND,0644);
	if(fd == -1)
        err_quit("open error");
	while(1){ 	
		t = time(0);
		char *buf = asctime(localtime(&t));
		write(fd,buf,strlen(buf));
		/*check wpa_supplicant*/
		get_task_pid("wpa_supplicant");
		get_task_pid("dhcpcd");
		if(-1 == get_task_pid("setup")){
			create_task("setup -p 4 > /setup.log &");
		}
		if(-1 == get_task_pid("bsa_server") || -1 == get_task_pid("app_manager")){
			create_task("bsa_ble_wifi_introducer.sh stop");
			create_task("bsa_ble_wifi_introducer.sh start");
		}
		get_task_pid("app_ble_wifi");
		
		sleep(60);
	}
	close(fd);
	exit(0);
}
/*name_srt length need less 16 bytes*/
pid_t get_task_pid(const char *name_str){
	pid_t pid = -1;
	char cmd[128] = {0};

	
	sprintf(cmd,"ps -e | grep \'%s\' | awk \'{print $1}\'",name_str);
    FILE *fp = popen(cmd, "r");
    char buffer[24] = {0};
    while (NULL != fgets(buffer, 23, fp)) //逐行读取执行结果并打印
    {
		memset(cmd,0,strlen(cmd));
        pid = atoi(buffer);
        sprintf(cmd,"%s PID: %d\n", name_str,pid);
		write(fd,cmd,strlen(cmd));
    }
    pclose(fp); //关闭返回的文件指针，注意不是用fclose噢

    return pid;
}

int create_task(const char *name_str){
	char cmd[128] = {0};

	signal(SIGCHLD,SIG_DFL); 
	if (-1 == system(name_str)) {
		sprintf(cmd,"%s start failed!\n", name_str);
        write(fd,cmd,strlen(cmd));
        return -1;
    }
	signal(SIGCHLD,SIG_IGN); 

	sprintf(cmd,"%s start succes!\n", name_str);
    write(fd,cmd,strlen(cmd));

	return 0;
}

void creat_daemon(){
	pid_t pid,sid;
	struct rlimit	rl;
	int i;	

	//ignore I/O signal，STOP signal
	signal(SIGTTOU,SIG_IGN);
	signal(SIGTTIN,SIG_IGN);
	signal(SIGTSTP,SIG_IGN);
	signal(SIGHUP,SIG_IGN);

        /*
    	* Clear file creation mask.
    	*/
   	umask(0);
	/*
    	* Get maximum number of file descriptors.
    	*/
    	if(getrlimit(RLIMIT_NOFILE, &rl) < 0)
        	err_quit(" can't get file limit");
	/*
    	* Become a session leader to lose controlling TTY.
    	*/
    	if((pid = fork()) < 0)
        	err_quit("can't fork");
    	else if (pid != 0)    /* parent */
        	exit(0);
	
    	setsid();

	if((pid = fork()) < 0)
        	err_quit("can't fork");
    	else if( pid != 0 )    /* parent */
        	exit(0);

	/*
    	* Change the current working directory to the root so
    	* we won't prevent file system from being unmounted.
    	*/
    	if(chdir("/") < 0)
        	err_quit("can't change directory to /");
 
	umask(0);
    	/*
    	* Close all open file descriptors.
    	*/
    	if(rl.rlim_max = RLIM_INFINITY)
        	rl.rlim_max = 1024;
    	for(i = 0; i < rl.rlim_max; i++)
        	close(i);
	
	//ignore SIGCHLD
	signal(SIGCHLD,SIG_IGN); 

	/*
    	* Attach file descriptors 0, 1, and 2 to /dev/null.
    	*/   
    	open("/dev/null", O_RDWR);
    	dup(0);
    	dup(0);

	return;
}

/*
 * Fatal error unrelated to a system call.
 * Error code passed as explict parameter.
 * Print a message and terminate.
 */
void
err_quit(const char *fmt, ...)
{
    perror(fmt);
    exit(1);
}
