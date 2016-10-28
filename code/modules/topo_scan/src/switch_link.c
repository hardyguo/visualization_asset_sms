/*
 * switch_link.c
 */
#include "switch_link.h"

int ports_get_type[128];
int count_get_port_type = 0;

extern int store_arp_info(char *ip, char *mac);
extern int store_rarp_info(char * ip, char * mac);
extern int store_fdb_info(switch_fdb_t *info);
extern int get_type_of_port();
extern int get_type_of_switch();

static void get_dev_arp_table_callback(snmp_arg *arg, char *value)
{
    int i,ret = 0;
    char *tmp_str = NULL;
    char ip_addr[MAX_IP_LEN] = {0};
    char mac[MAX_IP_LEN] = {0};
    char m1[8] = {0};
    char m2[8] = {0};
    char m3[8] = {0};
    char m4[8] = {0};
    char m5[8] = {0};
    char m6[8] = {0};

    if(NULL == value)
        return;

    tmp_str = strchr(value, '.') + 1;
	for(i=0; i<2; i++)
	{
		tmp_str = strchr(tmp_str, '.') + 1;
	}

    ret = sscanf(tmp_str, "%s = %s %s %s %s %s %s", ip_addr, m1, m2, m3, m4, m5, m6);
    if(7 != ret)
        return;
    sprintf(mac, "%s:%s:%s:%s:%s:%s", m1, m2, m3, m4, m5, m6);

    store_arp_info(ip_addr, mac);
	store_rarp_info(ip_addr, mac);

    return;
}

int get_arp_info(char *ipadd, char *read_key)
{
    int ret = 0;
    snmp_arg arg;
    memset(&arg, 0, sizeof(arg));

    assert(NULL!=ipadd && NULL!=read_key);

    arg.peer_name = strdup(ipadd);
    arg.community = strdup(read_key);
    arg.oid = strdup(PHYS_ADDRESS);

    ret = snmp_walk(&arg, get_dev_arp_table_callback, 1);
    if(ret)
    {
        _DEBUG_FILE("%s get the ip mask of ip(%s) using read key(%s), error\n", __func__, ipadd, read_key);
    }

    return ret;
}

static void get_switch_fdb_table_callback(snmp_arg *arg, char *value)
{
    int i,ret = 0;
	int max_by_fdb = 0;
    char *tmp_str = NULL;
    char m1[8] = {0};
    char m2[8] = {0};
    char m3[8] = {0};
    char m4[8] = {0};
    char m5[8] = {0};
    char m6[8] = {0};
    switch_fdb_t info;
    memset(&info, 0, sizeof(switch_fdb_t));

    if(NULL == value)
        return;

    tmp_str = strchr(value, '.') + 1;
	if(strcmp(arg->oid, TP_FDB2_PORT))
		max_by_fdb = 5;
	else
		max_by_fdb = 8;
	for(i=0; i<max_by_fdb; i++)
	{
		tmp_str = strchr(tmp_str, '.') + 1;
	}
	
    ret = sscanf(tmp_str, "%s = %d", info.mac, &info.port);
    if(2 != ret)
        return;
    ret = sscanf(info.mac, "%[^.].%[^.].%[^.].%[^.].%[^.].%[^.]", m1, m2, m3, m4, m5, m6);
    if(6 != ret)
        return;
    sprintf(info.mac, "%02X:%02X:%02X:%02X:%02X:%02X", atoi(m1), atoi(m2), atoi(m3), atoi(m4), atoi(m5), atoi(m6));
    strcpy(info.ip, arg->peer_name);

    store_fdb_info(&info);

    return;

}

int get_fdb_info(char *ipadd, char *read_key)
{
    int ret = 0;
    snmp_arg arg;
    memset(&arg, 0, sizeof(arg));

    assert(NULL!=ipadd && NULL!=read_key);

    arg.peer_name = strdup(ipadd);
    arg.community = strdup(read_key);
    arg.oid = strdup(TP_FDB_PORT);
retry_get_fdb:
    ret = snmp_walk(&arg, get_switch_fdb_table_callback, 1);
    if(ret)
    {
        _DEBUG_FILE("%s get the ip mask of ip(%s) using read key(%s) oid(%s), error\n", __func__, ipadd, read_key, arg.oid);
        if(0 == strcmp(arg.oid, TP_FDB_PORT))
        {
            arg.oid = strdup(TP_FDB2_PORT);
            _DEBUG_FILE("using oid(%s) retry\n", TP_FDB2_PORT);
            goto retry_get_fdb;
        }
    }
    else
    {
        _DEBUG_FILE("%s get the ip mask of ip(%s) using read key(%s) oid(%s), success\n", __func__, ipadd, read_key, arg.oid);
    }

    return ret;
}

static void get_base_port_table_callback(snmp_arg *arg, char *value)
{
    if(NULL == value)
        return;
    if(is_digital(value))
        return;
    ports_get_type[count_get_port_type++] = atoi(value);

    return;
}

int get_base_port(char *ipadd, char *read_key)
{
    int ret = 0;
    snmp_arg arg;
    memset(&arg, 0, sizeof(arg));

    assert(NULL!=ipadd && NULL!=read_key);

	count_get_port_type = 0;

    arg.peer_name = strdup(ipadd);
    arg.community = strdup(read_key);
    arg.oid = strdup(BASE_PORT);

    ret = snmp_walk(&arg, get_base_port_table_callback, 0);
    if(ret)
    {
        _DEBUG_FILE("%s get the ip mask of ip(%s) using read key(%s), error\n", __func__, ipadd, read_key);
    }

    return ret;
}

int get_switch_link()
{
	_DEBUG_FILE("\n--------------begin count switch link-------------\n");
    int ret = 0;

    ret = get_all_switch_info();
    if(ret)
    {
        return ret;
    }

	ret = get_flag_mac();
	if(ret)
	{
		return ret;
	}

	ret = get_core_ip_table();
	if(ret)
	{
		return ret;
	}

    ret = get_type_of_port();
    if(ret)
    {
        _DEBUG_FILE("get_type_of_port error\n");
    }

    ret = get_type_of_switch();
    if(ret)
    {
        _DEBUG_FILE("get_type_of_switch error\n");
    }

	ret = del_not_exist_2layer_switch();
	if(ret)
	{
		_DEBUG_FILE("del_not_exist_2layer_switch error\n");
	}

	_DEBUG_FILE("\n--------------end count switch link-------------\n");
    return ret;
}
