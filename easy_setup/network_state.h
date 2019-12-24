#ifndef __NETWORK_STATE_H__
#define __NETWORK_STATE_H__








int connect_check();

// function declare
int get_ip_by_domain(const char *domain, char *ip); // 根据域名获取ip
int get_local_mac(const char *eth_inf, char *mac); // 获取本机mac
int get_local_ip(const char *eth_inf, char *ip); // 获取本机ip
int get_ip();





#endif