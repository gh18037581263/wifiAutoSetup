#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include "easy_setup.h"
#include "ping.h"
#include "network_state.h"

int killed = 0;
int debug_enable = 1;
pthread_t net_thread = NULL;

#define WIFI_SSID_NAME_SIZE (33)
#define WIFI_SSID_PASS_SIZE (65)

static UINT8 wifi_introducer_char_ssid_value[WIFI_SSID_NAME_SIZE] = {0};
static UINT8 wifi_introducer_char_passphrase_value[WIFI_SSID_PASS_SIZE]  = {0};

static BOOLEAN wifi_introducer_ssid_name = FALSE;
static BOOLEAN wifi_introducer_ssid_password = FALSE;

static uint8 network_state = WIFI_DISCONNECTED;



void usage() {
    printf("-h: show help message\n");
    printf("-d: show debug message\n");
    printf("-k <v>: set 16-char key for all protocols\n");
    printf("-t <v>: easy_setup query timeout, default 60\n");
    printf("-n <v>: ap ssid, default: es\n");
    printf("-p <v>: bitmask of protocols to enable\n");
    printf("  0x%04x - mcast\n", 1<<EASY_SETUP_PROTO_BCAST);
    printf("  0x%04x - neeze\n", 1<<EASY_SETUP_PROTO_NEEZE);
    printf("  0x%04x - Air Kiss\n", 1<<EASY_SETUP_PROTO_AKISS);
    printf("  0x%04x - Xiaoyi\n", 1<<EASY_SETUP_PROTO_XIAOYI);
    printf("  0x%04x - changhong\n", 1<<EASY_SETUP_PROTO_CHANGHONG);
    printf("  0x%04x - jingdong\n", 1<<EASY_SETUP_PROTO_JINGDONG);
    printf("  0x%04x - jd JoyLink\n", 1<<EASY_SETUP_PROTO_JD);
    printf("  0x%04x - AP\n", 1<<EASY_SETUP_PROTO_AP);
}

static void signal_handler(int sig) {
    printf("aborted\n");
    killed = 1;
    if(SIGINT == sig || SIGTERM == sig){
        printf("net_thread child %d canceled safefly!\n",net_thread);
        pthread_cancel(net_thread);
    }

}
/*******************************************************************************
**
** Function         start_wpa_supplicant
**
** Description      wpa supplicant
**
** Returns          BOOLEAN
**
*******************************************************************************/
static BOOLEAN start_wpa_supplicant(void)
{
    FILE *fp = NULL;
    if ((fp = fopen("/etc/wpa_supplicant.conf", "w+")) == NULL)
    {
        LOGE("open wpa_supplicant.conf failed");
        return FALSE;
    }

    fprintf(fp, "%s\n", "ctrl_interface=/var/run/wpa_supplicant");
    fprintf(fp, "%s\n", "ap_scan=1");
    fprintf(fp, "%s\n", "network={");
    fprintf(fp, "%s%s%s\n", "ssid=\"", wifi_introducer_char_ssid_value, "\"");
    fprintf(fp, "%s%s%s\n", "psk=\"", wifi_introducer_char_passphrase_value, "\"");
    //fprintf(fp, "%s\n", "key_mgmt=WPA-PSK");
    fprintf(fp, "%s\n", "}");

    fclose(fp);
    fp = NULL;

#if 1
    if (-1 == system("killall wpa_supplicant;killall dhcpcd;"
                   "ifconfig wlan0 0.0.0.0")) {
        LOGE("killall wpa_supplicant dhcpcd failed");
        return FALSE;
    }

    if (-1 == system("wpa_supplicant -Dnl80211 -i wlan0 "
                   "-c /etc/wpa_supplicant.conf &")) {
        LOGE("start wpa_supplicant failed");
        return FALSE;
    }

    if (-1 == system("sleep 1;dhcpcd wlan0 -t 0 &")) {
        LOGE("dhcpcd failed");
        return FALSE;
    }
#else
    char buf[1024] = {0};
    if((fp = popen("killall wpa_supplicant;killall dhcpcd;""ifconfig wlan0 0.0.0.0","r")) == NULL){
        LOGE("killall wpa_supplicant dhcpcd failed");
        return FALSE;
    }
    while (fgets(buf,1024,fp) != NULL)
    {
        fprintf(stdout,"%s",buf);
    }
    pclose(fp);

    if((fp = popen("wpa_supplicant -Dnl80211 -i wlan0 ""-c /etc/wpa_supplicant.conf &","r")) == NULL){
        LOGE("start wpa_supplicant failed");
        return FALSE;
    }
    while (fgets(buf,1024,fp) != NULL)
    {
        fprintf(stdout,"%s",buf);
    }
    pclose(fp);

    if((fp = popen("sleep 1;dhcpcd wlan0 -t 0 &","r")) == NULL){
        LOGE("dhcpcd failed");
        return FALSE;
    }
    while (fgets(buf,1024,fp) != NULL)
    {
        fprintf(stdout,"%s",buf);
    }
    pclose(fp);
#endif

    return TRUE;
}

static int auto_start_wpa_supplicant(void)
{
    printf("ssid:%d psk:%d \n",wifi_introducer_ssid_name,wifi_introducer_ssid_password);
    if (!wifi_introducer_ssid_name || !wifi_introducer_ssid_password){
        printf("ssid psk error\n");
        return -1;
    }
    printf("killall\n");
#if 1
    if (-1 == system("killall wpa_supplicant;killall dhcpcd;"
                   "ifconfig wlan0 0.0.0.0")) {
        LOGE("killall wpa_supplicant dhcpcd failed");
        return -1;
    }
    printf("wpa_supplicant\n");
    if (-1 == system("wpa_supplicant -Dnl80211 -i wlan0 "
                   "-c /etc/wpa_supplicant.conf &")) {
        LOGE("start wpa_supplicant failed");
        return -1;
    }

    if (-1 == system("sleep 1;dhcpcd wlan0 -t 0 &")) {
        LOGE("dhcpcd failed");
        return -1;
    }
#else
    FILE *fp = NULL;
    char buf[1024] = {0};
    if((fp = popen("killall wpa_supplicant;killall dhcpcd;""ifconfig wlan0 0.0.0.0","r")) == NULL){
        LOGE("killall wpa_supplicant dhcpcd failed");
        return FALSE;
    }
    while (fgets(buf,1024,fp) != NULL)
    {
        fprintf(stdout,"%s",buf);
    }
    pclose(fp);

    if((fp = popen("wpa_supplicant -Dnl80211 -i wlan0 ""-c /etc/wpa_supplicant.conf &","r")) == NULL){
        LOGE("start wpa_supplicant failed");
        return FALSE;
    }
    while (fgets(buf,1024,fp) != NULL)
    {
        fprintf(stdout,"%s",buf);
    }
    pclose(fp);

    if((fp = popen("sleep 1;dhcpcd wlan0 -t 0 &","r")) == NULL){
        LOGE("dhcpcd failed");
        return FALSE;
    }
    while (fgets(buf,1024,fp) != NULL)
    {
        fprintf(stdout,"%s",buf);
    }
    pclose(fp);
#endif

    return 0;
}

/*******************************************************************************
**
** Function         is_ssid_configured
**
** Description      Check if configured
**
** Returns          void
**
*******************************************************************************/
static void is_ssid_configured(void)
{
    if (wifi_introducer_ssid_name && wifi_introducer_ssid_password)
    {

        if (!start_wpa_supplicant())
        {
            LOGE("start wpa_supplicant failed");
        }

        //wifi_introducer_ssid_name = FALSE;
        //wifi_introducer_ssid_password = FALSE;
        
    }
}

static int easy_setup_run(void)
{
    int ret;

    ret = easy_setup_start();
    if (ret) {
        LOGE("start easy_setup failed!\n");
        return ret;
    }

    /* query for result, blocks until mcast comes or times out */
    int start_time = clock();
    ret = easy_setup_query();
    if (!ret) {
        char *ssid = wifi_introducer_char_ssid_value; /* ssid of 32-char length, plus trailing '\0' */
        ret = easy_setup_get_ssid(ssid, sizeof(wifi_introducer_char_ssid_value));
        if (!ret) {
            wifi_introducer_ssid_name = TRUE;
            printf("ssid: %s\n", ssid);
        }

        char *password = wifi_introducer_char_passphrase_value; /* password is 64-char length, plus trailing '\0' */
        ret = easy_setup_get_password(password, sizeof(wifi_introducer_char_passphrase_value));
        if (!ret) {
            wifi_introducer_ssid_password = TRUE;
            printf("password: %s\n", password);
        }

        is_ssid_configured();
        
        uint8 protocol;
        ret = easy_setup_get_protocol(&protocol);
        if (ret) {
            printf("failed getting protocol.\n");
        } else if (protocol == EASY_SETUP_PROTO_BCAST) {
            char ip[16]; /* ipv4 max length */
            ret = mcast_get_sender_ip(ip, sizeof(ip));
            if (!ret) {
                printf("sender ip: %s\n", ip);
            }

            uint16 port;
            ret = mcast_get_sender_port(&port);
            if (!ret) {
                printf("sender port: %d\n", port);
            }
        } else if (protocol == EASY_SETUP_PROTO_NEEZE) {
            char ip[16]; /* ipv4 max length */
            ret = neeze_get_sender_ip(ip, sizeof(ip));
            if (!ret) {
                printf("sender ip: %s\n", ip);
            }

            uint16 port;
            ret = neeze_get_sender_port(&port);
            if (!ret) {
                printf("sender port: %d\n", port);
            }
        } else if (protocol == EASY_SETUP_PROTO_AKISS) {
            uint8_t random;
            ret = akiss_get_random(&random);
            if(!ret){
                printf("random:0x%02x\n",random);
            }
        }else if (protocol == EASY_SETUP_PROTO_AP) {
            char ip[16]; /* ipv4 max length */
            ret = ap_get_sender_ip(ip, sizeof(ip));
            if (!ret) {
                printf("sender ip: %s\n", ip);
            }

            uint16 port;
            ret = ap_get_sender_port(&port);
            if (!ret) {
                printf("sender port: %d\n", port);
            }
        }

#if 1
        /* if easy_setup_get_security() returns -1, try it more times */
        int tries = 3;
        while (tries--) {
            ret = easy_setup_get_security();
            if (ret != -1) break;
        }
        printf("security: ");
        if (ret == WLAN_SECURITY_WPA2) printf("wpa2\n");
        else if (ret == WLAN_SECURITY_WPA2_8021X) printf("wpa2-802.1x\n");
        else if (ret == WLAN_SECURITY_WPA) printf("wpa\n");
        else if (ret == WLAN_SECURITY_WEP) printf("wep\n");
        else if (ret == WLAN_SECURITY_NONE) printf("none\n");
        else printf("wpa2");
#endif

        LOGD("time elapsed: %lus\n", (clock()-start_time)/CLOCKS_PER_SEC);
    }

    /* must do this! */
    easy_setup_stop();

    if (wifi_introducer_ssid_name && wifi_introducer_ssid_password)
        return 0;
    else
    {
        return -1;
    }
    
}

void read_wifi_config(void)
{
    strcpy(wifi_introducer_char_ssid_value, get_string_from_ini("network", "ssid", NETWORK_CONFIG_ADDR));
    printf("ssid=%s",wifi_introducer_char_ssid_value);
    if(strlen(wifi_introducer_char_ssid_value))
        wifi_introducer_ssid_name = TRUE;
    strcpy(wifi_introducer_char_passphrase_value, get_string_from_ini("network", "psk", NETWORK_CONFIG_ADDR));
    printf("ssid=%s",wifi_introducer_char_passphrase_value);
    if(strlen(wifi_introducer_char_passphrase_value))
        wifi_introducer_ssid_password = TRUE;

}

int network_check()
{
    int i=20;
    while((i) && (0 != connect_check())){
        i--;
        sleep(1);  
    }
    if(i <= 0){
        network_state = WIFI_DISCONNECTED;
        return -1;
    }
    printf("wifi connected%d!\n",i);
    if(network_state == WIFI_DISCONNECTED)
        network_state = WIFI_CONNECTED;

    i=2;
    while(i--){
        sleep(1);
        if (0 == get_ip())
        {
            sleep(1);
            break;
        }
        printf("get_ip %ds!\n",20-i);
    }

    if(!PINGWAN){
        network_state = NET_CONNECTED;
        return 0;
    }
    else
    {
        network_state = NET_DISCONNECTED;
        return -1;
    }
    

}

void* network_fun(void* arg){
    int ret;
    while(1){
        pthread_setcancelstate(PTHREAD_CANCEL_ENABLE,NULL);
        pthread_testcancel();
        pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,NULL);

        network_check();
        switch (network_state)
        {
        case WIFI_DISCONNECTED:
            printf("WIFI_DISCONNECTED\n");
            int i = 2;
            while(i--){
                ret = auto_start_wpa_supplicant();
                if(!ret)break;
            }

            break;
        case WIFI_CONNECTED:
            printf("WIFI_CONNECTED\n");
            break;
        case NET_DISCONNECTED:
            printf("NET_DISCONNECTED\n");
            break;
        case NET_CONNECTED:
            printf("NET_CONNECTED\n");
            break;
        default:
            break;
        }
        sleep(60);
    }
}

int main(int argc, char* argv[])
{
    int ret = -1;
    int len;
    uint16 val;

    for (;;) {
        int c = getopt(argc, argv, "dhk:p:t:n:");
        if (c < 0) {
            break;
        }

        switch (c) {
            case 'd':
                debug_enable = 1;
                break;
            case 'k':
                mcast_set_key(optarg);
                neeze_set_key(optarg);
                akiss_set_key(optarg);
                jingdong_set_key(optarg);
                jd_set_key(optarg);
                ap_set_key(optarg);
                break;
            case 'p':
                sscanf(optarg, "%04x", (uint32*)&val);
                easy_setup_enable_protocols(val);
                break;
            case 't':
                sscanf(optarg, "%d", (uint32*)&val);
                easy_setup_set_timeout(val);
                break;
            case 'n':
                ap_set_ssid(optarg, strlen(optarg));
                break;
            case 'h':
                usage();
                return 0;
            default:
                usage();
                return 0;
        }
    }
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    read_wifi_config();
    ret = auto_start_wpa_supplicant();
    printf("auto_start_wpa_supplicant ret = %d\n",ret);
    while (ret)
    {
        if(killed)
            pthread_exit(NULL);
        printf("easy_setup_running!\n");
        ret = easy_setup_run();
        sleep(1);
    }
    
    ret = pthread_create(&net_thread,NULL,network_fun,NULL);
    if(ret != NULL){
        printf("network_thread start!");
        pthread_join(net_thread,NULL);
    }
    pthread_exit(NULL);
    return 0;
}

