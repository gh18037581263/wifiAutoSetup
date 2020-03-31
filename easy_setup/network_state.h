#ifndef __NETWORK_STATE_H__
#define __NETWORK_STATE_H__


enum {
    WIFI_DISCONNECTED = 0,
    WIFI_CONNECTED,
    NET_DISCONNECTED,
    NET_CONNECTED,
};

#define NETWORK_CONFIG_ADDR "/etc/wpa_supplicant.conf"


char *get_string_from_ini(char *title, char *key, char *filename);
int get_int_from_ini(char *title, char *key, char *filename);
int connect_check(void);

// function declare
int get_ip_by_domain(const char *domain, char *ip); // 根据域名获取ip
int get_local_mac(const char *eth_inf, char *mac); // 获取本机mac
int get_local_ip(const char *eth_inf, char *ip); // 获取本机ip
int get_ip();





#endif