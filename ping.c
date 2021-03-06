/*
 * @Author: D-lyw 
 * @Date: 2018-11-01 17:00:20 
 * @Last Modified by: D-lyw
 * @Last Modified time: 2018-12-01 17:01:42
 * @Description 在Linux环境利用socket编程,基于ICMP协议实现ping功能
 */
#include "ping.h"
#include <stdio.h>
#include <string.h>
#include <netdb.h>            // struct icpmhdr, struct iphdr , gethostbyname, hostent
#include <arpa/inet.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/ip_icmp.h>
#include <sys/time.h>
#include "network_state.h"

char sendbuf[1024];          // 用来存放将要发送的ip数据包
struct sockaddr_in sockaddr, recvsock;
int sockaddr_len = sizeof(struct sockaddr);
struct hostent *host;
char routeIP[24] = "192.168.1.1";
int sockfd = -1;

void closesocket(void){
    close(sockfd);
    sockfd = -1;
}

int set_icmp_socket(void){
    if(-1 != sockfd)
        return 0;

    // 创建原始套接字 SOCK_RAW 协议类型 IPPROTO_ICMP
    if((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1){
        fprintf(stderr, "%s\n", strerror(errno));
        return -1;
    }
    //设置超时
    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    if(setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout)) == -1){
        printf("set sent timeout error!\n");
        closesocket();
        return -1;
    }
    if(setsockopt(sockfd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout)) == -1){
        printf("set recv timeout error!\n");
        closesocket();
        return -1;
    }
    return 0;
}

int ping(const char *argv)
{
 
    int on = 1;
    int pid;
    int psend = 0, precv = 0;
    static char whereto[24];
    

    struct hostent *he;
    char hostname[20] = {0};
    gethostname(hostname,sizeof(hostname));
    he = gethostbyname(hostname);
    printf("hostname = %s ",hostname);
    printf("%s\n",inet_ntoa(*(struct in_addr*)(he->h_addr)));

    if(strcmp(whereto,argv) != 0){
        memset(&sockaddr, 0, sizeof(struct sockaddr));
        if((sockaddr.sin_addr.s_addr = inet_addr(argv)) == INADDR_NONE){
        // 说明输入的主机名不是点分十进制,采用域名方式解析
        if((host = gethostbyname(argv)) == NULL){
            fprintf(stderr, "ping %s , 未知的名称!\n", argv);
            return -1;
        }
        sockaddr.sin_addr = *(struct in_addr *)(host->h_addr);
        }
        sockaddr.sin_family = AF_INET;
        memcpy(whereto,argv,sizeof(argv));
    }


    //setuid(getpid());
    pid = getpid();

    // 发包操作
    printf("PINGing %s %d data send.socket %d\n", argv, ICMP_DATA_LEN,socket);
    static int i = 1;
    int recvDataLen;
    int sendDatalen;
    char recvbuf[1024];
    int ping_time = 3;
    int haveRespons = 0;
    while(ping_time--){
        int packlen = packping(i++);
        if(i > 512)i=1;
        if((sendDatalen = sendto(sockfd, sendbuf, packlen,0, (struct sockaddr *)&sockaddr, sizeof(sockaddr))) < 0){
             fprintf(stderr, "send ping package %d error, %s\n", i, strerror(errno));
             continue ;
        }
 
        if((recvDataLen = recvfrom(sockfd, recvbuf, sizeof(recvbuf), 0, (struct sockaddr *)&recvsock, &sockaddr_len)) == -1){
            fprintf(stderr, "recvmsg error, %s\n", strerror(errno));
            continue;
        }

        if(0 != decodepack(recvbuf, recvDataLen)){
            printf("decodepack error! \n");
            return -1;
        }
        else
        {
            haveRespons++;
        }
        
        usleep(100000);
    }

    if(!haveRespons){     
        return -1;
    }

    
    return 0;
}

// 发送ping数据包
int packping(int sendsqe){
    struct icmp *icmp_hdr;  // icmp头部指针

    icmp_hdr = (struct icmp *)sendbuf;
    icmp_hdr->icmp_type = ICMP_ECHO;
    icmp_hdr->icmp_code = 0;
    icmp_hdr->icmp_hun.ih_idseq.icd_id = getpid();
    icmp_hdr->icmp_hun.ih_idseq.icd_seq = sendsqe;
    memset(icmp_hdr->icmp_data, 0, ICMP_DATA_LEN);
    gettimeofday((struct timeval *)icmp_hdr->icmp_data, NULL);

    int icmp_total_len = 8 + ICMP_DATA_LEN;

    icmp_hdr->icmp_cksum = 0;
    icmp_hdr->icmp_cksum = checksum((unsigned char *)(sendbuf),icmp_total_len);

    return icmp_total_len;
}

int decodepack(char *buf, int len){
    struct iphdr *ip_hdr;
    struct icmp *icmp_hdr;
    int iph_lenthg;
    float rtt; // 往返时间  
    struct timeval end; // 接收报文时的时间戳

    ip_hdr = (struct iphdr *)buf;
    // ip头部长度
    iph_lenthg = ip_hdr->ihl<<2;
    
    icmp_hdr = (struct icmp *)(buf + iph_lenthg);

    // icmp报文的长度
    len -= iph_lenthg;
    if(len < 8){
        fprintf(stderr, "Icmp package length less 8 bytes , error!\n");
        return -1;
    }

    // 确认是本机发出的icmp报文的响应
    if(icmp_hdr->icmp_type != ICMP_ECHOREPLY || icmp_hdr->icmp_hun.ih_idseq.icd_id != getpid()){
        fprintf(stderr, "Don't send to us!");
        return -1;
    }
    gettimeofday(&end, NULL);
    rtt = timesubtract((struct timeval *)&icmp_hdr->icmp_data, &end);
    printf("Received %d bytes from %s, ttl = %d, rtt = %0.3f ms, icmpseq = %d \n", len, inet_ntoa(recvsock.sin_addr),ip_hdr->ttl, rtt, icmp_hdr->icmp_seq);

    return 0;
}

// 计算时间差
float timesubtract(struct timeval *begin, struct timeval *end){
    int n;// 先计算两个时间点相差多少微秒
    n = ( end->tv_sec - begin->tv_sec ) * 1000000
        + ( end->tv_usec - begin->tv_usec );
    // 转化为毫秒返回
    return (float) (n / 1000.0);
}

// 校验和生成
uint16 checksum(unsigned char *buf, int len){
    unsigned int sum=0;
    unsigned short *cbuf;

    cbuf=(unsigned short *)buf;

    while(len>1){
        sum+=*cbuf++;
        len-=2;
    }

    if(len)
        sum+=*(unsigned char *)cbuf;

    sum=(sum>>16)+(sum & 0xffff);
    sum+=(sum>>16);

    return ~sum;
}


int get_route_IP(void){
    int ret = -1;
    int i = 0;
    FILE *fp = popen("route -n | awk \'{print $2}\' | sed -n \"3p\"", "r");
    if(fp != NULL)
        memset(routeIP,0,sizeof(routeIP));
    while (NULL != fgets(routeIP, 23, fp)) //逐行读取执行结果并打印
    {
        printf("route IP: %s %u\n", routeIP,IPStrToInt(routeIP));
        if(IPStrToInt(routeIP) != 0)
            ret = 0; 
    }
    pclose(fp); //关闭返回的文件指针，注意不是用fclose噢

    return ret;
}

