#ifndef __SOCPUBLIC_H__
#define __SOCPUBLIC_H__

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <time.h>
#include <glib.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <mysql.h>

/*
 *thread use
 */
#include <unistd.h>
#include <sys/types.h>
#include <pthread.h>
#include <assert.h>
#include <math.h>

#include "thread_pool.h"
#include "handle_snmp.h"
#include "switch_link.h"
#include "main.h"

#define SERVER_PORT 7887

#define SUCCESS 		           	0
#define ERROR   			        -1
#define ERR_NULL_PARAMETER			-2

#define LOG_DIR			    		"/var/log/topo"
#define LOG_TOPO                    LOG_DIR"/scan_debug"
#define LOG_FILE_INFO				LOG_DIR"/scan_info"

#define TOPOSCANFLAG_BEGIN 			0
#define TOPOSCANFLAG_END 			1

#define THREAD_NUM              	20
#define MAX_IP_LEN                  64
#define SNMP_RETURN_LEN             256
#define SNMP_MAXOID		            64

#define SQL_LEN 					512

/*
 *dev type
 */
#define SERVERS_TYPE		       	9
#define SWITCH_2LAYER_SNMP_TYPE		10
#define PRINTER_TYPE     			11
#define SWITCH_3LAYER_TYPE			12
#define ROUTE_TYPE					13
#define DEV_TYPE			      	14
#define GATE_DEV_TYPE               15
#define HOST_TYPE       			16
#define SWITCH_2LAYER_TYPE     		17
#define WIRELESS_ROUTE_TYPE 		18
#define SUBNET_TYPE               	-19

/*
 *snmp version
 */
#define SNMP_VERSION_1	            0
#define SNMP_VERSION_2c             1
#define SNMP_VERSION_3              3

#define DIRECT                      3
#define INDIRECT                    4

#define FORWARDING                  1
#define NOTFORWARDING               2

#define COMM_READ_KEY               "public"

#define DEFAULT_SNMP_RETIRES        0

/*
 *public oid
 */
#define OID_SYS_DESC                ".1.3.6.1.2.1.1.1.0"
#define OID_SYS_OBJECT_ID 			".1.3.6.1.2.1.1.2.0"
#define OID_SYS_UPTIME              ".1.3.6.1.2.1.1.3.0"
#define OID_SYS_CONTACT             ".1.3.6.1.2.1.1.4.0"
#define OID_SYS_NAME 				".1.3.6.1.2.1.1.5.0"
#define OID_SYS_LOCATION			".1.3.6.1.2.1.1.6.0"
#define OID_SYS_SERVICES            ".1.3.6.1.2.1.1.7.0"

#define OID_IFPHY_ADDR              ".1.3.6.1.2.1.2.2.1.6"

#define OID_IP_FORWARDING           ".1.3.6.1.2.1.4.1.0"

#define OID_IP_ADDR                 ".1.3.6.1.2.1.4.20.1.1"
#define OID_IP_IFINDEX              ".1.3.6.1.2.1.4.20.1.2"
#define OID_IP_MASK                 ".1.3.6.1.2.1.4.20.1.3"

#define OID_ROUTE_DEST              ".1.3.6.1.2.1.4.21.1.1"
#define OID_ROUTE_IFINDEX           ".1.3.6.1.2.1.4.21.1.2"
#define OID_ROUTE_NEXTHOP           ".1.3.6.1.2.1.4.21.1.7"
#define OID_ROUTE_TYPE              ".1.3.6.1.2.1.4.21.1.8"
#define OID_ROUTE_MASK              ".1.3.6.1.2.1.4.21.1.11"

#define OID_ENTERPRISES				".1.3.6.1.4.1"

#define OID_BASE_NUM_PORTS          ".1.3.6.1.2.1.17.1.2.0"
#define OID_STP_ROOT_COST           ".1.3.6.1.2.1.17.2.6.0"
#define OID_STP_ROOT_PORT           ".1.3.6.1.2.1.17.2.7.0"
#define OID_FDB_ADDRESS             ".1.3.6.1.2.1.17.4.3.1.1"

#define OID_PRINTER_GENERAL         ".1.3.6.1.2.1.43.5.1.1"
#define OID_PRINTER_CHANGES         ".1.3.6.1.2.1.43.5.1.1.1.1"
#define OID_PRINTER_RESET           ".1.3.6.1.2.1.43.5.1.1.3.1"
#define OID_PRINTER_GCO             ".1.3.6.1.2.1.43.5.1.1.4.1"
#define OID_PRINTER_GSP             ".1.3.6.1.2.1.43.5.1.1.5.1"
#define OID_PRINTER_CNODL           ".1.3.6.1.2.1.43.5.1.1.11.1"
#define OID_PRINTER_CNODC           ".1.3.6.1.2.1.43.5.1.1.12.1"
#define OID_PRINTER_CD              ".1.3.6.1.2.1.43.5.1.1.13.1"

#define IS_VALID_IP(ip)          	strcmp(ip, "127.0.0.1") && strcmp(ip, "0.0.0.0") && strcmp(ip, "255.0.0.0")

/*
PORT      STATE  SERVICE
21/tcp    open   ftp
22/tcp    open   ssh
23/tcp    closed telnet
25/tcp    closed smtp
53/tcp    closed domain
67/tcp    closed dhcps
80/tcp    closed http
110/tcp   closed pop3
143/tcp   closed imap
443/tcp   open   https
1433/tcp  closed ms-sql-s
1521/tcp  closed oracle
3306/tcp  open   mysql
5000/tcp  closed sybase
5432/tcp  closed postgresql
8080/tcp  open   http-proxy
50000/tcp closed ibm-db2
161/udp   open   snmp
*/
#define NMAP_SCAN_TCP_PORT              "21,22,23,25,53,67,80,110,143,443,1433,1521,3306,5000,5432,8080,50000"
/*
nmap -n -sS -sU -p T:80,21,22,3306,8888,U:161 10.0.13.0/24 -T 5
-T<0-5>: Set timing template (higher is faster)
*/
#define NMAP_SCAN                       "nmap -n -sS -sU -p T:%s,U:%d %s -T %d"

typedef struct _ip_route_table
{
    char dest[MAX_IP_LEN];
    int index;
    char next_hop[MAX_IP_LEN];
    int type;
    char mask[MAX_IP_LEN];

} ip_route_table;

typedef struct _ip_addr_table
{
    char addr[MAX_IP_LEN];
    int index;
    char mask[MAX_IP_LEN];

} ip_addr_table;

typedef struct _topo_relation
{
    int topo_layer;
    char dev_name[64];
    char dev_ip[MAX_IP_LEN];
    char dev_mask[MAX_IP_LEN];
    char pre_ip[MAX_IP_LEN];
    int dev_type;
    char read_key[128];
	int snmp_version;

} topo_relation;

typedef struct _topo_config
{
    char core_ip[MAX_IP_LEN];
    int scan_layer;
    long snmp_version;
    int scan_port;
    int icmptimeout;
    int snmptimeout;
    char read_key[128];
    char write_key[128];
    int scan_result;
    char subnetinfo[1024];
    int asset_transform;
    int max_thread;
    int retries;

} topo_config;

typedef struct _server_info
{
    char port[16];
    char state[16];
    char service[16];

} server_info;

typedef struct _service_port_info
{
    unsigned char ftp;
    unsigned char ssh;
    unsigned char telnet;
    unsigned char smtp;
    unsigned char domain;
    unsigned char dhcps;
    unsigned char http;
    unsigned char pop3;
    unsigned char imap;
    unsigned char https;
    unsigned char ms_sql_s;
    unsigned char oracle;
    unsigned char mysql;
    unsigned char sybase;
    unsigned char postgresql;
    unsigned char http_proxy;
    unsigned char ibm_db2;
    unsigned char snmp;

} service_port_info;

typedef struct _topo_send_msg
{
    char dev_name[64];
    char dev_ip[32];
    char dev_mask[32];
    char pre_ip[32];
    int dev_type;
    int asset_transform;
    int icmptimeout;
    int snmptimeout;
    char read_key[128];
    char write_key[128];
    service_port_info sp;
	int snmp_port;
	int snmp_version;

} topo_send_msg;

void _DEBUG_FILE(char *fmt, ...);
void _DEBUG_INFO(char *fmt, ...);
void signal_pro();
int signal_init();
int create_hash_table();
int store_topo2hash(char *my_hashkey,topo_relation* my_hashvalue, service_port_info *sp_info);
int free_all_hash_table();
int topo_hash_info_show();
int init_db();
int get_scan_state();
int set_scan_flag(int flag);
int store_core_ip_info();
int dev_scan(int scan_layer, char *scan_ip);
int get_scan_dev(int scan_layer, char scan_ipadd[][MAX_IP_LEN]);
int real_ipaddr(char *ipadd);
int topo_relation_store2db(topo_relation *topoNodeinfo);
int get_sys_cmd_ouput(const char*cmd,char*output,int len);
int get_dev_name(char *ipadd, char *read_key, char *devname, int *snmp_version);
int store_dev_ip_mask(char *ip, ip_addr_table *value);
int get_subnet_pool( char *ipadd,char *ipmask, char *subnet_ip1,char *subnet_ip2,char *ipbroadcast);
int store_route_info(ip_route_table *tmp_value);
int is_valid_ipv4_addr(char *str_ip, struct in_addr *addr);
int is_invalid_mac(const char*mac);
int get_subnet_filter_range();
int is_digital(const char *value);
int db_close();
int init_time_check_socket();
void close_time_check_socket();
int subnet_info2db();
int store_dev_direct_nexthop(char *ip);
int get_all_switch_info();
int get_flag_mac();
int get_self_ip(char *core_ip, char *self_ip);
int same_subnet(struct in_addr *first, struct in_addr *second, struct in_addr *mask);
int clean_links_db();
int link_hash_info_show();
int get_flag_mac_list(char *ip);
int get_core_ip_table();
int del_not_exist_2layer_switch();
int netmask_str2len(char* mask);
char* netmask_len2str(int mask_len, char* mask_str);
void *mysql_process();
int read_topo_config(topo_config *);
int store_hosts2db(input_host *, output_host *);

#endif
