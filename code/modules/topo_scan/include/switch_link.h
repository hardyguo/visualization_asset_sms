#ifndef _SWITCH_LINK_H_
#define _SWITCH_LINK_H_

#include "common.h"

#define TP_FDB_PORT "1.3.6.1.2.1.17.4.3.1.2"
#define PHYS_ADDRESS "1.3.6.1.2.1.3.1.1.2"
#define BASE_PORT "1.3.6.1.2.1.17.1.4.1.1"
#define BASE_PORT_IFINDEX "1.3.6.1.2.1.17.1.4.1.2"
#define TP_FDB2_PORT "1.3.6.1.2.1.17.7.1.2.2.1.2"

#define TYPE_SWITCH_LEAF 1
#define TYPE_SWITCH_PSEUDO_LEAF 2

#define TYPE_PORT_UP 1
#define TYPE_PORT_DOWN 2
#define TYPE_PORT_LEAF 3

#define MAX_IP_LEN 64

typedef struct switch_fdb
{
    char ip[MAX_IP_LEN];
    int port;
    char mac[32];

} switch_fdb_t;

typedef struct switch_port
{
    char ip[MAX_IP_LEN];
    int port;
    char type_port;

} switch_port_t;

typedef struct switch_link
{
    char ip[MAX_IP_LEN];
    char read_key[32];
    char type_switch;

} switch_link_t;

typedef struct switch_port_index
{
    char ip[MAX_IP_LEN];
    int port;
    int if_index;

} switch_port_index_t;

typedef struct link
{
    char name[2*MAX_IP_LEN];	/*链路名称*/
    int link_type;				/*链路类型*/
    char up_ip[MAX_IP_LEN];		/*上行设备*/
    int up_port;				/*上行接口*/
    char down_ip[MAX_IP_LEN];	/*下行设备*/
    int down_port;				/*下行接口*/
	
} link_t;

int get_switch_link();
int get_fdb_info(char *ipadd, char *read_key);
int get_arp_info(char *ipadd, char *read_key);
int get_base_port(char *ipadd, char *read_key);


#endif /*_SWITCH_LINK_H_*/
