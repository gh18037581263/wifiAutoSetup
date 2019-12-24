#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <stdlib.h>
#include "easy_setup.h"
#include "ping.h"
#include "network_state.h"

int killed = 0;
int debug_enable = 1;

#define WIFI_SSID_NAME_SIZE (33)
#define WIFI_SSID_PASS_SIZE (65)

static UINT8 wifi_introducer_char_ssid_value[WIFI_SSID_NAME_SIZE] = {0};
static UINT8 wifi_introducer_char_passphrase_value[WIFI_SSID_PASS_SIZE]  = {0};

static BOOLEAN wifi_introducer_ssid_name = FALSE;
static BOOLEAN wifi_introducer_ssid_password = FALSE;

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
    if ((fp = fopen("/data/cfg/wpa_supplicant.conf", "w+")) == NULL)
    {
        LOGE("open wpa_supplicant.conf failed");
        return FALSE;
    }

    fprintf(fp, "%s\n", "ctrl_interface=/var/run/wpa_supplicant");
    fprintf(fp, "%s\n", "ap_scan=1");
    fprintf(fp, "%s\n", "network={");
    fprintf(fp, "%s%s%s\n", "ssid=\"", wifi_introducer_char_ssid_value, "\"");
    fprintf(fp, "%s%s%s\n", "psk=\"", wifi_introducer_char_passphrase_value, "\"");
    fprintf(fp, "%s\n", "key_mgmt=WPA-PSK");
    fprintf(fp, "%s\n", "}");

    fclose(fp);

    if (-1 == system("killall wpa_supplicant;killall dhcpcd;"
                   "ifconfig wlan0 0.0.0.0")) {
        LOGE("killall wpa_supplicant dhcpcd failed");
        return FALSE;
    }

    if (-1 == system("wpa_supplicant -Dnl80211 -i wlan0 "
                   "-c /data/cfg/wpa_supplicant.conf &")) {
        LOGE("start wpa_supplicant failed");
        return FALSE;
    }

    if (-1 == system("sleep 1;dhcpcd wlan0 -t 0 &")) {
        LOGE("dhcpcd failed");
        return FALSE;
    }

    return TRUE;
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

        wifi_introducer_ssid_name = FALSE;
        wifi_introducer_ssid_password = FALSE;
        
    }
}

int main(int argc, char* argv[])
{
    int ret;
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

    ret = easy_setup_start();
    if (ret) return ret;

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
            uint8 random;
            ret = akiss_get_random(&random);
            if (!ret) {
                printf("random: 0x%02x\n", random);
            }
        } else if (protocol == EASY_SETUP_PROTO_CHANGHONG) {
            uint8 sec;
            ret = changhong_get_sec_mode(&sec);
            if (!ret) {
                printf("sec mode: 0x%02x\n", sec);
            }
        } else if (protocol == EASY_SETUP_PROTO_JINGDONG) {
            uint8 sec;
            ret = jingdong_get_sec_mode(&sec);
            if (!ret) {
                printf("sec mode: 0x%02x\n", sec);
            }
        } else if (protocol == EASY_SETUP_PROTO_JD) {
            uint8 crc;
            ret = jd_get_crc(&crc);
            if (!ret) {
                printf("crc: 0x%02x\n", crc);
            }

            uint32 ip;
            ret = jd_get_ip(&ip);
            if (!ret) {
                printf("ip: 0x%08x\n", ip);
            }

            uint16 port;
            ret = jd_get_port(&port);
            if (!ret) {
                printf("port: 0x%04x\n", port);
            }
        } else if (protocol == EASY_SETUP_PROTO_XIAOYI) {
            uint8 buf[128];
            uint8 len = sizeof(buf);
            ret = xiaoyi_get_buffer(&len, buf);
            if (!ret) {
                printf("buf(%d) - ", len);
                int i;
                for (i=0; i<len; i++) printf("%02x ", buf[i]);
                printf("\n");
            }
        } else if (protocol == EASY_SETUP_PROTO_AP) {
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

#if 0
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

    while(0 != connect_check()){
        sleep(1);
        printf("wifi connected!\n");
    }
    
    int i=30;
    while(i--){
        sleep(1);
        if (0 == get_ip())
        {
            sleep(1);
            break;
        }
        printf("get_ip %ds!\n",30-i);
    }

    i = 3;
    while(i--){
        printf("i=%d\n",i);
        sleep(3);
        if(!PINGWLAN)
            PINGWAN;
    }
    return 0;
}

