#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netdb.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/types.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdarg.h>
#include "network_state.h"
#include "ping.h"
 

#define MAC_SIZE    18
#define IP_SIZE     16


const char *test_domain = "www.baidu.com";
const char *test_eth = "wlan0";


//read string from config file
char *get_string_from_ini(char *title, char *key, char *filename)
{
    FILE *fp;
    char szLine[1024];
    static char tmpstr[1024];
    int rtnval;
    int i = 0;
    int flag = 0;
    char *tmp;

    if ((fp = fopen(filename, "r")) == NULL)
    {
        perror("fopen()");
        return "";
    }

    while (!feof(fp))
    {
        rtnval = fgetc(fp);

        if (rtnval == EOF)
        {
            break;
        }
        else
        {
            szLine[i++] = rtnval;
        }

        if (rtnval == '\n')
        {
            szLine[--i] = '\n';
            i = 0;
            tmp = strchr(szLine, '=');

            if ((tmp != NULL) && (flag == 1))
            {
                if (strstr(szLine, key) != NULL)
                {
					//comment
                    if ('#' == szLine[0]);
                    else if ('/' == szLine[0] && '/' == szLine[1]);
                    else
                    {
						//local key position
                        strcpy(tmpstr, tmp + 1);
                        fclose(fp);
						//printf("tmpstr:%s\n",tmpstr);
                        return tmpstr;
                    }
                }
            }
            else
            {
                //strcpy(tmpstr, "[");
                strcpy(tmpstr, title);
                strcat(tmpstr, "=");
				//printf("tmpstr:%s\n",tmpstr);
                if (strncmp(tmpstr, szLine, strlen(tmpstr)) == 0)
                {
					//encounter title
                    flag = 1;
                }
            }
            memset(szLine,0,sizeof(szLine));
	}
	
    }

    fclose(fp);
    return "";
}

int get_int_from_ini(char *title, char *key, char *filename)
{
    return atoi(get_string_from_ini(title, key, filename));
}


int connect_check(void)
{
	
	int net_fd;
	char statue[20];
	
	net_fd=open("/sys/class/net/wlan0/operstate",O_RDONLY);//以只读的方式打开/sys/class/net/wlan0/operstate
	if(net_fd<0)
	{
	
		printf("open err\n");
		return -1;
	}
	
	printf("open success\n");
	memset(statue,0,sizeof(statue));
    int ret=read(net_fd,statue,10);
    printf("statue is %s",statue);
	close(net_fd);
	if(NULL!=strstr(statue,"up"))
	{
		printf("on line\n");
		return 0;
	}
	else if(NULL!=strstr(statue,"down"))
	{
	   printf("off line\n");
	   return -1;
	}
	else
	{
		printf("unknown err\n");
		return -1;
	}
	return -1;
}

 
/**
 进程名可以不等于执行文件名。
 这时要传递另外一个参数。
不考虑进程名是pts这种故意捣乱的情况。
通过ps，检查输出结果是否是进程名。
参考字串如下：
　9548 pts/19   00:00:25 gh_main
 */
int   process_check_state(const char* psProcessName)
{
    int state = -1;
    
    FILE *fstream=NULL;    
    char buff[1024] = {0};
 
    //用空格，是去掉类似dah_main的噪声
    sprintf(buff, "ps -A | grep \" %s\"", psProcessName); 
    if (NULL==(fstream=popen(buff, "r")))
    {
        return -1;
    }
 
    while (NULL != fgets(buff, sizeof(buff), fstream))
    {
        if (strlen(buff) <= 0)
        {
            break;
        }
        
        char* psHead = strstr(buff, psProcessName);
        if (psHead == NULL)
        {
            continue;
        }
 
        int pos = strlen(psHead)-1;
        if (psHead[pos] == '\n')
        {
            psHead[pos] = 0;
        }
 
        //GH_LOG_INFO("|||%s|||", psHead);
        if (!strcmp(psHead, psProcessName))
        {
            state = 0;
            break;
        }
    }
 
    pclose(fstream);
    
    return state;
}

// 根据域名获取ip
int get_ip_by_domain(const char *domain, char *ip)
{
    char **pptr;
    struct hostent *hptr;

    hptr = gethostbyname(domain);
    if(NULL == hptr)
    {
        printf("gethostbyname error for host:%s/n", domain);
        return -1;
    }

    for(pptr = hptr->h_addr_list ; *pptr != NULL; pptr++)
    {
        if (NULL != inet_ntop(hptr->h_addrtype, *pptr, ip, IP_SIZE) )
        {
            return 0; // 只获取第一个 ip
        }
    }

    return -1;
}

// 获取本机mac
int get_local_mac(const char *eth_inf, char *mac)
{
    struct ifreq ifr;
    int sd;

    bzero(&ifr, sizeof(struct ifreq));
    if( (sd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("get %s mac address socket creat error\n", eth_inf);
        return -1;
    }

    strncpy(ifr.ifr_name, eth_inf, sizeof(ifr.ifr_name) - 1);

    if(ioctl(sd, SIOCGIFHWADDR, &ifr) < 0)
    {
        printf("get %s mac address error\n", eth_inf);
        close(sd);
        return -1;
    }

    snprintf(mac, MAC_SIZE, "%02x:%02x:%02x:%02x:%02x:%02x",
        (unsigned char)ifr.ifr_hwaddr.sa_data[0],
        (unsigned char)ifr.ifr_hwaddr.sa_data[1],
        (unsigned char)ifr.ifr_hwaddr.sa_data[2],
        (unsigned char)ifr.ifr_hwaddr.sa_data[3],
        (unsigned char)ifr.ifr_hwaddr.sa_data[4],
        (unsigned char)ifr.ifr_hwaddr.sa_data[5]);

    close(sd);

    return 0;
}


// 获取本机ip
int get_local_ip(const char *eth_inf, char *ip)
{
    int sd;
    struct sockaddr_in sin;
    struct ifreq ifr;

    sd = socket(AF_INET, SOCK_DGRAM, 0);
    if (-1 == sd)
    {
        printf("socket error: %s\n", strerror(errno));
        return -1;
    }

    strncpy(ifr.ifr_name, eth_inf, IFNAMSIZ);
    ifr.ifr_name[IFNAMSIZ - 1] = 0;

    // if error: No such device
    if (ioctl(sd, SIOCGIFADDR, &ifr) < 0)
    {
        printf("ioctl error: %s\n", strerror(errno));
        close(sd);
        return -1;
    }

    memcpy(&sin, &ifr.ifr_addr, sizeof(sin));
    snprintf(ip, IP_SIZE, "%s", inet_ntoa(sin.sin_addr));

    close(sd);
    return 0;
}

//IP字符串转32位int数 
unsigned int IPStrToInt(const char *ip)
{
	unsigned uResult = 0;
	int nShift = 24;
	int temp = 0;
	const char *pStart = ip;
	const char *pEnd = ip;
	
	while (*pEnd != '\0')
	{
		while (*pEnd!='.' && *pEnd!='\0')
		{
			pEnd++;
		}
		temp = 0;
		for (pStart; pStart!=pEnd; ++pStart)
		{
			temp = temp * 10 + *pStart - '0';
		}	
		
		uResult += temp<<nShift;
		nShift -= 8;
		
		if (*pEnd == '\0')
			break;
		pStart = pEnd + 1;
		pEnd++;
	}
	
	return uResult;
} 
 
//将整数IP地址转换成字符串IP地址 
char *IntToStr(const unsigned int ip, char *buf)
{
	sprintf(buf, "%u.%u.%u.%u",
		(unsigned char )*((char *)&ip + 3),
		(unsigned char )*((char *)&ip + 2),
		(unsigned char )*((char *)&ip + 1),
		(unsigned char )*((char *)&ip + 0));
	return buf;
}


int get_ip(){
	char ip[IP_SIZE];
    char mac[MAC_SIZE];

    get_ip_by_domain(test_domain, ip);

    printf("%s ip: %s\n", test_domain, ip);

    if(0 != get_local_mac(test_eth, mac))
		return -1;
    printf("local %s mac: %s\n", test_eth, mac);

    if(0 != get_local_ip(test_eth, ip))
		return -1;
    printf("local %s ip: %s\n", test_eth, ip);
	unsigned int IP_32 = IPStrToInt(ip);
	IP_32 |= 0xFF;
	IP_32 &= 0xFFFFFF01;
	IntToStr(IP_32,ip);
	printf("route ip: %s\n", ip); 
	memcpy(routeIP,ip,sizeof(ip));

    return 0;
}