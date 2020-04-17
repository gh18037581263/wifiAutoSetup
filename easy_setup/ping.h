#ifndef __PING_H__
#define __PING_H__

#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <unistd.h>
#include <error.h>
#include "common.h"

#define IPVERSION 4
#define ICMP_DATA_LEN 56


int packping(int sendsqe);
uint16 checksum(unsigned char *buf, int len);
int decodepack(char *buf, int len);
float timesubtract(struct timeval *begin, struct timeval *end);
int ping(const char *argv);
int get_route_IP(void);
int set_icmp_socket(void);
void closesocket(void);
extern char routeIP[];

#define PINGWAN     ping("www.baidu.com")
#define PINGWLAN    ping(routeIP)


#endif