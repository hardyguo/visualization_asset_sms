#include "common.h"

static int sockfd;
static struct sockaddr_in addr;

GHashTable *topo_hashtable = NULL;
GHashTable *dev_interface_hashtable = NULL;
GHashTable *dev_route_hashtable = NULL;
GHashTable *dev_direct_nexthop_hashtable = NULL;

GHashTable *switch_hashtable = NULL;
GHashTable *switch_fdb_hashtable = NULL;
GHashTable *switch_port_hashtable = NULL;
GHashTable *arp_hashtable = NULL;
GHashTable *rarp_hashtable = NULL;
GHashTable *link_hashtable = NULL;

char flag_mac[32] = {0};
int core_mac_num = 0;
char flag_core_mac[128][32] = {{0}};


pthread_mutex_t hash_topo_mutex = PTHREAD_MUTEX_INITIALIZER;

extern topo_config my_config_info;
extern int ports_get_type[128];
extern int count_get_port_type;
extern int links2db(link_t *info);

int init_time_check_socket()
{
    /*启动socket服务端*/
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(ERROR == sockfd)
    {
        _DEBUG_FILE("%s init socket error, and errno is %s\n", __func__, strerror(errno));
        return ERROR;
    }
    // 填充服务端的资料
    bzero(&addr, sizeof(struct sockaddr_in));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(SERVER_PORT);
    if(inet_aton("127.0.0.1", &addr.sin_addr) < 0)
    {
        _DEBUG_FILE("%s ip error, and errno is %s\n", __func__, strerror(errno));
        return ERROR;
    }

    return SUCCESS;
}

void close_time_check_socket()
{
    close(sockfd);
}

int create_hash_table()
{
    topo_hashtable = g_hash_table_new(g_str_hash, g_str_equal);
    dev_interface_hashtable = g_hash_table_new(g_str_hash, g_str_equal);
    dev_route_hashtable = g_hash_table_new(g_str_hash, g_str_equal);
    dev_direct_nexthop_hashtable = g_hash_table_new(g_str_hash, g_str_equal);
    switch_hashtable = g_hash_table_new(g_str_hash, g_str_equal);
    switch_port_hashtable = g_hash_table_new(g_str_hash, g_str_equal);
    switch_fdb_hashtable = g_hash_table_new(g_str_hash, g_str_equal);
    arp_hashtable = g_hash_table_new(g_str_hash, g_str_equal);
    rarp_hashtable = g_hash_table_new(g_str_hash, g_str_equal);
    link_hashtable = g_hash_table_new(g_str_hash, g_str_equal);

    if(NULL == topo_hashtable
            || NULL == dev_interface_hashtable
            || NULL == dev_route_hashtable
            || NULL == dev_direct_nexthop_hashtable
            || NULL == switch_hashtable
            || NULL == switch_port_hashtable
            || NULL == arp_hashtable
            || NULL == rarp_hashtable
            || NULL == switch_fdb_hashtable
            || NULL == link_hashtable)
        return ERROR;
    else
        return SUCCESS;
}

void udpc_request(int sockfd, const struct sockaddr_in *addr, topo_relation *my_hashvalue, service_port_info *sp_info)
{
    int ret = 0;
    topo_send_msg *p_tp_hashvalue = NULL;
    p_tp_hashvalue = (topo_send_msg *)malloc(sizeof(topo_send_msg));
    if (NULL == p_tp_hashvalue)
    {
        _DEBUG_FILE(" hash key malloc error!!!");
        return;
    }
    bzero(p_tp_hashvalue, sizeof(topo_send_msg));

    strcpy(p_tp_hashvalue->dev_name, my_hashvalue->dev_name);
    strcpy(p_tp_hashvalue->dev_ip, my_hashvalue->dev_ip);
    strcpy(p_tp_hashvalue->dev_mask, my_hashvalue->dev_mask);
    strcpy(p_tp_hashvalue->pre_ip, my_hashvalue->pre_ip);
    p_tp_hashvalue->dev_type = my_hashvalue->dev_type;
    strcpy(p_tp_hashvalue->read_key, my_hashvalue->read_key);
	p_tp_hashvalue->snmp_version = my_hashvalue->snmp_version;
    p_tp_hashvalue->asset_transform = my_config_info.asset_transform;
    p_tp_hashvalue->icmptimeout = my_config_info.icmptimeout;
    p_tp_hashvalue->snmptimeout = my_config_info.snmptimeout;
    strcpy(p_tp_hashvalue->write_key, my_config_info.write_key);
	p_tp_hashvalue->snmp_port = my_config_info.scan_port;

    if(SERVERS_TYPE == p_tp_hashvalue->dev_type && NULL != sp_info)
    {
        p_tp_hashvalue->sp.ftp = sp_info->ftp;
        p_tp_hashvalue->sp.ssh = sp_info->ssh;
        p_tp_hashvalue->sp.telnet = sp_info->telnet;
        p_tp_hashvalue->sp.smtp = sp_info->smtp;
        p_tp_hashvalue->sp.domain = sp_info->domain;
        p_tp_hashvalue->sp.dhcps = sp_info->dhcps;
        p_tp_hashvalue->sp.http = sp_info->http;
        p_tp_hashvalue->sp.pop3 = sp_info->pop3;
        p_tp_hashvalue->sp.imap = sp_info->imap;
        p_tp_hashvalue->sp.https = sp_info->https;
        p_tp_hashvalue->sp.ms_sql_s = sp_info->ms_sql_s;
        p_tp_hashvalue->sp.oracle = sp_info->oracle;
        p_tp_hashvalue->sp.mysql = sp_info->mysql;
        p_tp_hashvalue->sp.sybase = sp_info->sybase;
        p_tp_hashvalue->sp.postgresql = sp_info->postgresql;
        p_tp_hashvalue->sp.http_proxy = sp_info->http_proxy;
        p_tp_hashvalue->sp.ibm_db2 = sp_info->ibm_db2;
        p_tp_hashvalue->sp.snmp = sp_info->snmp;
    }

    ret = sendto(sockfd, p_tp_hashvalue, sizeof(topo_send_msg), 0, (struct sockaddr *)addr, sizeof(struct sockaddr));
    if(ERROR == ret)
        _DEBUG_FILE("send to server ip = %s error\n", p_tp_hashvalue->dev_ip);
    else
        _DEBUG_FILE("send to server ip = %s\n", p_tp_hashvalue->dev_ip);

    if(p_tp_hashvalue != NULL)
    {
        free(p_tp_hashvalue);
        p_tp_hashvalue = NULL;
    }

    return;
}

int store_topo2hash(char *my_hashkey, topo_relation* my_hashvalue, service_port_info *sp_info)
{
    char *topo_hashkey;
    topo_relation *p_tp_hashvalue=NULL;
    topo_relation *pre_subnet = NULL;

    assert(my_hashkey!=NULL && my_hashvalue!=NULL);

    if(NULL==topo_hashtable)
        return ERR_NULL_PARAMETER;

    topo_hashkey=(char *) malloc(MAX_IP_LEN);
    if(NULL==topo_hashkey)
    {
        _DEBUG_FILE("%s hash key malloc error\n", __func__);
        return ERR_NULL_PARAMETER;
    }
    memset(topo_hashkey, 0, MAX_IP_LEN);
    strcpy(topo_hashkey, my_hashkey);


    p_tp_hashvalue = (topo_relation *)g_hash_table_lookup(topo_hashtable,topo_hashkey);
    if(NULL == p_tp_hashvalue)
    {
        p_tp_hashvalue = (topo_relation *)malloc(sizeof(topo_relation));
        if (NULL == p_tp_hashvalue)
        {
            free(topo_hashkey);
            topo_hashkey = NULL;
            _DEBUG_FILE("%s hash key malloc error\n", __func__);
            return ERR_NULL_PARAMETER;
        }
        memset(p_tp_hashvalue, 0, sizeof(topo_relation));

        p_tp_hashvalue->topo_layer = my_hashvalue->topo_layer;
        strcpy(p_tp_hashvalue->dev_name, my_hashvalue->dev_name);
        strcpy(p_tp_hashvalue->dev_ip, topo_hashkey);
        strcpy(p_tp_hashvalue->dev_mask, my_hashvalue->dev_mask);
        strcpy(p_tp_hashvalue->pre_ip, my_hashvalue->pre_ip);
        p_tp_hashvalue->dev_type = my_hashvalue->dev_type;
        strcpy(p_tp_hashvalue->read_key, my_hashvalue->read_key);
		p_tp_hashvalue->snmp_version = my_hashvalue->snmp_version;

        _DEBUG_FILE("[ dev_ip:%s  ", p_tp_hashvalue->dev_ip);
        _DEBUG_FILE("dev_mask:%s  ", p_tp_hashvalue->dev_mask);
        _DEBUG_FILE("dev_name:%s  ", p_tp_hashvalue->dev_name);
        _DEBUG_FILE("dev_type:%d  ", p_tp_hashvalue->dev_type);
        _DEBUG_FILE("pre_ip:%s  ", p_tp_hashvalue->pre_ip);
        _DEBUG_FILE("topo_layer:%d  ", p_tp_hashvalue->topo_layer);
		_DEBUG_FILE("snmp_version:%d  ", p_tp_hashvalue->snmp_version);
        _DEBUG_FILE("read_key:%s ]\n", p_tp_hashvalue->read_key);

        pthread_mutex_lock(&hash_topo_mutex);
        g_hash_table_insert(topo_hashtable,topo_hashkey,p_tp_hashvalue);
        pthread_mutex_unlock(&hash_topo_mutex);

        /*This feature is temporarily blocked*/
        /*send to time check */
        if(p_tp_hashvalue->dev_type!=SUBNET_TYPE && p_tp_hashvalue->dev_type!=SWITCH_2LAYER_TYPE && 0)
        {
            udpc_request(sockfd, &addr, p_tp_hashvalue, sp_info);
        }

        /*change subnet to 2lswitch if have host/servers */
        pre_subnet = (topo_relation *)g_hash_table_lookup(topo_hashtable, p_tp_hashvalue->pre_ip);
        if(NULL != pre_subnet && pre_subnet->dev_type == SUBNET_TYPE)
        {
            pre_subnet->dev_type = SWITCH_2LAYER_TYPE;
        }

    }
    else
    {
        free(topo_hashkey);
        topo_hashkey = NULL;
        _DEBUG_FILE("%s the ip(%s) is exist\n", __func__, my_hashkey);
        return ERROR;
    }

    return SUCCESS;
}

int store_dev_ip_mask(char *ip, ip_addr_table *tmp_value)
{
    char *key_ip = NULL;
    ip_addr_table *value = NULL;

    assert(ip!=NULL && tmp_value!=NULL);

    if(NULL == dev_interface_hashtable)
        return ERROR;

    key_ip = (char *)malloc(MAX_IP_LEN);
    if(NULL == key_ip)
    {
        _DEBUG_FILE(" hash key malloc error!!!");
        return ERROR;
    }
    memset(key_ip, 0, MAX_IP_LEN);
    strcpy(key_ip, ip);

    value = (ip_addr_table *)g_hash_table_lookup(dev_interface_hashtable, key_ip);
    if(NULL == value)
    {
        value = (ip_addr_table *)malloc(sizeof(ip_addr_table));
        if(NULL == value)
        {
            free(key_ip);
            key_ip = NULL;
            _DEBUG_FILE("%s malloc error\n", __func__);
            return ERROR;
        }
        memset(value, 0, sizeof(ip_addr_table));
        strcpy(value->addr, key_ip);
        strcpy(value->mask, tmp_value->mask);
        value->index = tmp_value->index;

        g_hash_table_insert(dev_interface_hashtable, key_ip, value);
        _DEBUG_FILE("%s insert ip(%s) ifindex(%d) mask(%s) \n", __func__, key_ip, value->index, value->mask);
    }
    else
    {
        free(key_ip);
        key_ip = NULL;
        _DEBUG_FILE("%s error ip addr \n", __func__);
        return ERROR;
    }

    return SUCCESS;
}

int store_route_info(ip_route_table *tmp_value)
{
    char *key_dest = NULL;
    ip_route_table *value = NULL;

    if(NULL == dev_route_hashtable)
        return ERROR;

    key_dest = (char *)malloc(MAX_IP_LEN);
    if(NULL == key_dest)
    {
        _DEBUG_FILE("%s hash key malloc error\n", __func__);
        return ERROR;
    }
    memset(key_dest, 0, MAX_IP_LEN);
    strcpy(key_dest, tmp_value->dest);

    value = (ip_route_table *)g_hash_table_lookup(dev_route_hashtable, key_dest);
    if(NULL == value)
    {
        value = (ip_route_table *)malloc(sizeof(ip_route_table));
        if(NULL == value)
        {
            free(key_dest);
            key_dest = NULL;
            _DEBUG_FILE("%s malloc error\n", __func__);
            return ERROR;
        }
        memset(value, 0, sizeof(ip_route_table));

        strcpy(value->dest, tmp_value->dest);
        strcpy(value->next_hop, tmp_value->next_hop);
        value->type = tmp_value->type;
        strcpy(value->mask, tmp_value->mask);

        g_hash_table_insert(dev_route_hashtable, key_dest, value);
        _DEBUG_FILE("%s insert route dest(%s) nexthop(%s)\n", __func__, key_dest, value->next_hop);
    }
    else
    {
        free(key_dest);
        key_dest = NULL;
        _DEBUG_FILE("%s error route dest nexthop\n", __func__);
        return ERROR;
    }

    return SUCCESS;
}

int free_hash_table(GHashTable * hashtable)
{
    GList *list=NULL;

    if(NULL==hashtable)
        return ERROR;

    list = g_hash_table_get_values(hashtable);
    while(list != NULL)
    {
        g_list_free(list);
        list = g_list_next(list);
    }
    g_hash_table_destroy(hashtable);

    return SUCCESS;
}

int free_all_hash_table()
{
    free_hash_table(topo_hashtable);
    free_hash_table(dev_interface_hashtable);
    free_hash_table(dev_route_hashtable);
    free_hash_table(dev_direct_nexthop_hashtable);
    free_hash_table(switch_hashtable);
    free_hash_table(switch_port_hashtable);
    free_hash_table(switch_fdb_hashtable);
    free_hash_table(arp_hashtable);
    free_hash_table(rarp_hashtable);
    free_hash_table(link_hashtable);

    return SUCCESS;
}

int get_scan_dev(int scan_layer, char scan_ipadd[][MAX_IP_LEN])
{
    GList *list = NULL;
    topo_relation *p_tp_hashshow=NULL;
    int i=0;

    _DEBUG_FILE("topo hash size:%u\n", g_hash_table_size(topo_hashtable));
    list = g_hash_table_get_values(topo_hashtable);
    while(list != NULL)
    {
        p_tp_hashshow = (topo_relation *)list->data;

        /*_DEBUG_FILE("dev_ip:%s  ", p_tp_hashshow->dev_ip);
        _DEBUG_FILE("dev_mask:%s  ", p_tp_hashshow->dev_mask);
        _DEBUG_FILE("dev_name:%s  ", p_tp_hashshow->dev_name);
        _DEBUG_FILE("dev_type:%d  ", p_tp_hashshow->dev_type);
        _DEBUG_FILE("pre_ip:%s  ", p_tp_hashshow->pre_ip);
        _DEBUG_FILE("topo_layer:%d\n", p_tp_hashshow->topo_layer);*/

        if((p_tp_hashshow->topo_layer == scan_layer)
                && ((p_tp_hashshow->dev_type == DEV_TYPE)
                    || (p_tp_hashshow->dev_type == ROUTE_TYPE)
                    || (p_tp_hashshow->dev_type == SWITCH_3LAYER_TYPE)
                    || (p_tp_hashshow->dev_type == SWITCH_2LAYER_SNMP_TYPE)))
        {
            strcpy(scan_ipadd[i], p_tp_hashshow->dev_ip);
            _DEBUG_FILE("Hash table find ip is %s and type is %d\n", p_tp_hashshow->dev_ip, p_tp_hashshow->dev_type);
            i++;
        }
        list = g_list_next(list);
    }
    g_list_free(list);
    list = NULL;

    return i;
}

int topo_hash_info_show()
{
    int i = 0;
    GList *list = NULL;
    topo_relation *p_tp_hashshow=NULL;

    list = g_hash_table_get_values(topo_hashtable);
    while(list != NULL)
    {
        p_tp_hashshow = (topo_relation *)list->data;
        if(real_ipaddr(p_tp_hashshow->dev_ip))
        {
            list = g_list_next(list);
            i++;
            continue;
        }

        if((real_ipaddr(p_tp_hashshow->dev_mask))
                && (p_tp_hashshow->topo_layer != 0))
        {
            list = g_list_next(list);
            i++;
            continue;
        }
        if((real_ipaddr(p_tp_hashshow->pre_ip))
                &&(p_tp_hashshow->topo_layer != 0))
        {
            list = g_list_next(list);
            i++;
            continue;
        }
        _DEBUG_FILE("------------------------------------------\n");
        _DEBUG_FILE("topo_layer is %d  ",p_tp_hashshow->topo_layer);
        _DEBUG_FILE("dev name is %s  ",p_tp_hashshow->dev_name);
        _DEBUG_FILE("dev ip is %s  ",p_tp_hashshow->dev_ip);
        _DEBUG_FILE("dev ipmask is %s  ",p_tp_hashshow->dev_mask);
        _DEBUG_FILE("dev pre ip is %s  ",p_tp_hashshow->pre_ip);
        _DEBUG_FILE("type is %d }\n",p_tp_hashshow->dev_type);
        topo_relation_store2db(p_tp_hashshow);
        list = g_list_next(list);
        i++;
    }
    g_list_free(list);
    list = NULL;

    _DEBUG_FILE("all info count is %d\n",i);

    return SUCCESS;
}

int link_hash_info_show()
{
    int i = 0;
    GList *list = NULL;
    link_t *info = NULL;

    list = g_hash_table_get_values(link_hashtable);
    while(list != NULL)
    {
        info = (link_t *)list->data;
        links2db(info);
        list = g_list_next(list);
        i++;
    }
    g_list_free(list);
    list = NULL;

    return SUCCESS;
}

int store_dev_direct_nexthop(char *ip)
{
    char *key_ip = NULL;
    char *value = NULL;

    assert(ip!=NULL);

    if(NULL == dev_direct_nexthop_hashtable)
        return ERROR;

    key_ip = (char *)malloc(MAX_IP_LEN);
    if(NULL == key_ip)
    {
        _DEBUG_FILE(" hash key malloc error!!!");
        return ERROR;
    }
    memset(key_ip, 0, MAX_IP_LEN);
    strcpy(key_ip, ip);

    value = (char *)g_hash_table_lookup(dev_direct_nexthop_hashtable, key_ip);
    if(NULL == value)
    {
        value = (char *)malloc(MAX_IP_LEN);
        if(NULL == value)
        {
            free(key_ip);
            key_ip = NULL;
            _DEBUG_FILE("%s malloc error\n", __func__);
            return ERROR;
        }
        memset(value, 0, MAX_IP_LEN);
        strcpy(value, key_ip);

        g_hash_table_insert(dev_direct_nexthop_hashtable, key_ip, value);
        _DEBUG_FILE("%s insert ip(%s) value(%s) \n", __func__, key_ip, value);
    }
    else
    {
        free(key_ip);
        key_ip = NULL;
        _DEBUG_FILE("%s error ip addr \n", __func__);
        return ERROR;
    }

    return SUCCESS;
}

int get_all_switch_info()
{
    int ret = 0;
    GList *list = NULL;
    topo_relation *p_tp_hashshow = NULL;
    char *ip_addr = NULL;
    switch_link_t *value = NULL;

    list = g_hash_table_get_values(topo_hashtable);
    while(list != NULL)
    {
        p_tp_hashshow = (topo_relation *)list->data;
        if(real_ipaddr(p_tp_hashshow->dev_ip))
        {
            list = g_list_next(list);
            continue;
        }

        if(p_tp_hashshow->dev_type == SWITCH_3LAYER_TYPE
                || p_tp_hashshow->dev_type == SWITCH_2LAYER_SNMP_TYPE)
        {
            ip_addr = (char *)malloc(sizeof(char) * MAX_IP_LEN);
            if(NULL == ip_addr)
            {
                _DEBUG_FILE("%s malloc error!\n", __func__);
                ret = ERROR;
                goto free_list;
            }
            strcpy(ip_addr, p_tp_hashshow->dev_ip);
            value = (switch_link_t *)g_hash_table_lookup(switch_hashtable, ip_addr);
            if(NULL == value)
            {
                value = (switch_link_t *)malloc(sizeof(switch_link_t));
                if(NULL == value)
                {
                    free(ip_addr);
                    ip_addr = NULL;
                    _DEBUG_FILE("%s malloc error!\n", __func__);
                    ret = ERROR;
                    goto free_list;
                }
                memset(value, 0, sizeof(switch_link_t));
                strcpy(value->ip, ip_addr);
                strcpy(value->read_key, p_tp_hashshow->read_key);

                g_hash_table_insert(switch_hashtable, ip_addr, value);
                _DEBUG_FILE("%s insert switch ip(%s)\n", __func__, ip_addr);
            }
            else
            {
                free(ip_addr);
                ip_addr = NULL;
                ret = ERROR;
                goto list_next;
            }

            ret = get_fdb_info(p_tp_hashshow->dev_ip, p_tp_hashshow->read_key);
        }

        if(p_tp_hashshow->dev_type == SWITCH_3LAYER_TYPE
                || p_tp_hashshow->dev_type == ROUTE_TYPE)
            get_arp_info(p_tp_hashshow->dev_ip, p_tp_hashshow->read_key);

list_next:
        list = g_list_next(list);
    }
free_list:
    g_list_free(list);
    list = NULL;

    return ret;
}

int store_arp_info(char *ip, char *mac)
{
    char *key_ip = NULL;
    char *value = NULL;

    if(ip == NULL || mac == NULL || NULL == arp_hashtable)
        return ERROR;

    key_ip = (char *)malloc(MAX_IP_LEN);
    if(NULL == key_ip)
    {
        _DEBUG_FILE(" hash key malloc error!!!");
        return ERROR;
    }
    memset(key_ip, 0, MAX_IP_LEN);
    strcpy(key_ip, ip);

    value = (char *)g_hash_table_lookup(arp_hashtable, key_ip);
    if(NULL == value)
    {
        value = (char *)malloc(sizeof(char)*32);
        if(NULL == value)
        {
            free(key_ip);
            key_ip = NULL;
            _DEBUG_FILE("%s malloc error\n", __func__);
            return ERROR;
        }
        memset(value, 0, sizeof(char)*32);
        strcpy(value, mac);

        g_hash_table_insert(arp_hashtable, key_ip, value);
        _DEBUG_FILE("%s insert ip(%s) value(%s) \n", __func__, key_ip, value);
    }
    else
    {
        free(key_ip);
        key_ip = NULL;
        _DEBUG_FILE("%s error ip addr \n", __func__);
        return ERROR;
    }

    return SUCCESS;
}

int store_rarp_info(char *ip, char *mac)
{
    char *key_mac = NULL;
    char *value = NULL;

    if(ip == NULL || mac == NULL || NULL == rarp_hashtable)
        return ERROR;

    key_mac = (char *)malloc(sizeof(char)*32);
    if(NULL == key_mac)
    {
        _DEBUG_FILE(" hash key malloc error!!!");
        return ERROR;
    }
    memset(key_mac, 0, sizeof(char)*32);
    strcpy(key_mac, mac);

    value = (char *)g_hash_table_lookup(rarp_hashtable, key_mac);
    if(NULL == value)
    {
        value = (char *)malloc(MAX_IP_LEN);
        if(NULL == value)
        {
            free(key_mac);
            key_mac = NULL;
            _DEBUG_FILE("%s malloc error\n", __func__);
            return ERROR;
        }
        memset(value, 0, MAX_IP_LEN);
        strcpy(value, ip);

        g_hash_table_insert(rarp_hashtable, key_mac, value);
        _DEBUG_FILE("%s insert mac(%s) ip(%s) \n", __func__, key_mac, value);
    }
    else
    {
        free(key_mac);
        key_mac = NULL;
        _DEBUG_FILE("%s error mac\n", __func__);
        return ERROR;
    }

    return SUCCESS;
}

int store_link_info(link_t *info)
{
    char *key_name= NULL;
    link_t *value = NULL;

    if(info == NULL || NULL == link_hashtable)
        return ERROR;

    key_name = (char *)malloc(sizeof(char)*2*MAX_IP_LEN);
    if(NULL == key_name)
    {
        _DEBUG_FILE(" hash key malloc error!!!");
        return ERROR;
    }
    memset(key_name, 0, sizeof(char)*2*MAX_IP_LEN);
    sprintf(info->name, "%s_%d/%s_%d", info->up_ip, info->up_port, info->down_ip, info->down_port);
    strcpy(key_name, info->name);

    value = (link_t *)g_hash_table_lookup(link_hashtable, key_name);
    if(NULL == value)
    {
        value = (link_t *)malloc(sizeof(link_t));
        if(NULL == value)
        {
            free(key_name);
            key_name = NULL;
            _DEBUG_FILE("%s malloc error\n", __func__);
            return ERROR;
        }
        memset(value, 0, sizeof(link_t));
        value->link_type = info->link_type;
        strcpy(value->name, info->name);
        strcpy(value->up_ip, info->up_ip);
        strcpy(value->down_ip, info->down_ip);
        value->up_port = info->up_port;
        value->down_port = info->down_port;

        g_hash_table_insert(link_hashtable, key_name, value);
        _DEBUG_FILE("%s insert link(%s)\n", __func__, key_name);
    }
    else
    {
        free(key_name);
        key_name = NULL;
        _DEBUG_FILE("%s error mac\n", __func__);
        return ERROR;
    }

    return SUCCESS;
}

int store_fdb_info(switch_fdb_t *info)
{
    char *key_value = NULL;
    switch_fdb_t *info_value = NULL;

    if(info == NULL || NULL == switch_fdb_hashtable)
        return ERROR;

    key_value = (char *)malloc(128);
    if(NULL == key_value)
    {
        _DEBUG_FILE(" hash key malloc error!!!");
        return ERROR;
    }
    memset(key_value, 0, 128);
    sprintf(key_value, "%s_%d_%s", info->ip, info->port, info->mac);
    info_value = (switch_fdb_t *)g_hash_table_lookup(switch_fdb_hashtable, key_value);
    if(NULL == info_value)
    {
        info_value = (switch_fdb_t *)malloc(sizeof(switch_fdb_t));
        if(NULL == info_value)
        {
            free(key_value);
            key_value = NULL;
            _DEBUG_FILE("%s malloc error\n", __func__);
            return ERROR;
        }
        memset(info_value, 0, sizeof(switch_fdb_t));
        strcpy(info_value->ip, info->ip);
        info_value->port = info->port;
        strcpy(info_value->mac, info->mac);

        g_hash_table_insert(switch_fdb_hashtable, key_value, info_value);
        _DEBUG_FILE("%s insert value(%s)\n", __func__, key_value);
    }
    else
    {
        free(key_value);
        key_value = NULL;
        _DEBUG_FILE("%s error ip addr \n", __func__);
        return ERROR;
    }

    return SUCCESS;
}

int get_flag_mac()
{
    int ret = 0;
    char *value = NULL;
    char ip_addr[MAX_IP_LEN] = {0};

    ret = get_self_ip(my_config_info.core_ip, ip_addr);
    if(ret)
    {
        _DEBUG_FILE("%s get_self_ip ret(%d) error!\n", __func__, ret);
        return ERROR;
    }
    _DEBUG_FILE("%s get_self_ip ip(%s) success\n", __func__, ip_addr);

    value = (char *)g_hash_table_lookup(arp_hashtable, ip_addr);
    if(NULL != value)
    {
        strcpy(flag_mac, value);
        _DEBUG_FILE("%s mac(%s)\n", __func__, flag_mac);
        return SUCCESS;
    }

    return ERROR;
}

static int check_switch_mac(char *mac)
{
    int ret = 0;
    GList *list = NULL;
    switch_link_t *value = NULL;
    char *switch_mac = NULL;

    list = g_hash_table_get_values(switch_hashtable);
    while(list != NULL)
    {
        value = (switch_link_t *)list->data;
		if(strcasecmp(value->ip, my_config_info.core_ip))
		{
	        switch_mac = (char *)g_hash_table_lookup(arp_hashtable, value->ip);
	        if(NULL != switch_mac)
	        {
	            if(0 == strcasecmp(mac, switch_mac))
	            {
	                ret = ERROR;
	                goto free_list;
	            }
	        }
		}
        list = g_list_next(list);
    }
free_list:
    g_list_free(list);
    list = NULL;

    return ret;
}

static int update_type_port(switch_port_t *info)
{
    switch_port_t *value = NULL;
    char *tmp_key = NULL;

    if(NULL == info || NULL == switch_port_hashtable)
        return ERROR;

    tmp_key = (char *)malloc(MAX_IP_LEN+sizeof(int));
    if(NULL == tmp_key)
    {
        _DEBUG_FILE("%s malloc error\n", __func__);
        return ERROR;
    }
    sprintf(tmp_key, "%s_%d", info->ip, info->port);
    value = (switch_port_t *)g_hash_table_lookup(switch_port_hashtable, tmp_key);
    if(NULL == value)
    {
        value = malloc(sizeof(switch_port_t));
        if(NULL == value)
        {
            free(tmp_key);
            tmp_key = NULL;
            _DEBUG_FILE("%s malloc error\n", __func__);
            return ERROR;
        }
        strcpy(value->ip, info->ip);
        value->port = info->port;
        value->type_port = info->type_port;

        g_hash_table_insert(switch_port_hashtable, tmp_key, value);
        _DEBUG_FILE("%s insert key(%s) switch(%s) port(%d) type(%d)\n", __func__, tmp_key, value->ip, value->port, value->type_port);
    }
    else
    {
        free(tmp_key);
        tmp_key = NULL;
    }

    return SUCCESS;
}

static int update_before_ip(char *mac, char *before_ip)
{
    char *ip_addr = NULL;
    topo_relation *info = NULL;

    if(NULL == mac)
        return ERROR;

    ip_addr = (char *)g_hash_table_lookup(rarp_hashtable, mac);
    if(NULL != ip_addr)
    {
        info = (topo_relation *)g_hash_table_lookup(topo_hashtable, ip_addr);
        if(NULL != info)
        {
            _DEBUG_FILE("%s %s from %s ", __func__, ip_addr, info->pre_ip);
            strcpy(info->pre_ip, before_ip);
            _DEBUG_FILE("to %s\n", info->pre_ip);
        }
    }

    return SUCCESS;
}

int get_flag_mac_list(char *ip)
{
    char *mac = NULL;

    if(NULL == ip)
        return ERROR;

    mac = (char *)g_hash_table_lookup(arp_hashtable, ip);
    if(NULL != mac)
    {
        strcpy(flag_core_mac[core_mac_num++], mac);
    }

    return SUCCESS;
}

int get_type_of_port()
{
    int ret = 0;
    GList *list = NULL;
    switch_fdb_t *value = NULL;
    switch_port_t info;
    GList *switch_list = NULL;
    switch_link_t *switch_value = NULL;
    char macs[1024][32] = {{0}};
    int i = 0;
    int j = 0;
    int m = 0;
    int k = 0;
    char *ip_addr = NULL;
    char tmp_ip[MAX_IP_LEN] = {0};
    topo_relation *topo_info;
    link_t link_info;

    switch_list = g_hash_table_get_values(switch_hashtable);
    while(switch_list != NULL)
    {
        switch_value = (switch_link_t *)switch_list->data;
        ret = get_base_port(switch_value->ip, switch_value->read_key);
        if(ret)
            goto next_switch;

        _DEBUG_FILE("--\n");
        for(j = 0; j < count_get_port_type; j++)
        {
            list = g_hash_table_get_values(switch_fdb_hashtable);
            while(list != NULL)
            {
                value = (switch_fdb_t *)list->data;
                if(0 == strcasecmp(value->ip, switch_value->ip)
                        && ports_get_type[j] == value->port)
                {
                    strcpy(macs[i++], value->mac);
                }

                list = g_list_next(list);
            }
            g_list_free(list);
            list = NULL;

            memset(&info, 0, sizeof(switch_port_t));
            if(i < 1)
				continue;//info.type_port = TYPE_PORT_DOWN;
            //else if(1 == i)
            info.type_port = TYPE_PORT_LEAF;

            for(m = 0; m < i; m++)
            {
                if(0 == strcasecmp(flag_mac, macs[m]))
                {
                    info.type_port = TYPE_PORT_UP;
                    break;
                }

                ret = check_switch_mac(macs[m]);
                if(ret)
                {
                    info.type_port = TYPE_PORT_DOWN;
                    break;
                }

                /*get the up port of connect 3 layer core switch*/
                if(strcasecmp(my_config_info.core_ip, switch_value->ip))
                {
                    for(k = 0; k < core_mac_num; k++)
                    {
                        if(0 == strcasecmp(flag_core_mac[k], macs[m]))
                        {
                            info.type_port = TYPE_PORT_UP;
                            break;
                        }
                    }
                }
            }
            strcpy(info.ip, switch_value->ip);
            info.port = ports_get_type[j];

            update_type_port(&info);

            /*update the ip of leaf port*/
            if(info.type_port == TYPE_PORT_LEAF && 1 == i)
            {
                update_before_ip(macs[0], info.ip);
            }

            /*get down links*/
            for(m = 0; m < i; m++)
            {
                ip_addr = (char *)g_hash_table_lookup(rarp_hashtable, macs[m]);
                if(NULL != ip_addr)
                {
                    strcpy(tmp_ip, ip_addr);
find_before:
                    topo_info = (topo_relation *)g_hash_table_lookup(topo_hashtable, tmp_ip);
                    if(NULL != topo_info)
                    {
						if(topo_info->dev_type == SERVERS_TYPE
							|| topo_info->dev_type == PRINTER_TYPE
							|| topo_info->dev_type == HOST_TYPE)
							continue;
                        if(strcmp(topo_info->pre_ip, info.ip))
                        {
                            strcpy(tmp_ip, topo_info->pre_ip);
                            goto find_before;
                        }
                        else
                        {
                            memset(&link_info, 0, sizeof(link_t));
                            strcpy(link_info.up_ip, info.ip);
                            strcpy(link_info.down_ip, tmp_ip);
                            link_info.up_port = info.port;
                            store_link_info(&link_info);
                            break;
                        }
                    }
                }
            }

			/*get up links*/
            if(strcasecmp(my_config_info.core_ip, switch_value->ip)
                    && info.type_port == TYPE_PORT_UP)
            {
                topo_info = (topo_relation *)g_hash_table_lookup(topo_hashtable, switch_value->ip);
                if(NULL != topo_info)
                {
                    memset(&link_info, 0, sizeof(link_t));
                    strcpy(link_info.up_ip, topo_info->pre_ip);
                    strcpy(link_info.down_ip, switch_value->ip);
                    link_info.down_port = info.port;
                    store_link_info(&link_info);
                }
            }

            i = 0;
        }
        _DEBUG_FILE("--\n");
next_switch:
        switch_list = g_list_next(switch_list);
    }
    g_list_free(switch_list);
    switch_list = NULL;

    return ret;
}

static void update_switch_type(gpointer key, gpointer value, gpointer user_data)
{
    int ret = 0;
    GList *list = NULL;
    switch_link_t *switch_value = NULL;
    switch_port_t *switch_port = NULL;
    char type_ports_coll[128] = {0};
    int i = 0;
    int j = 0;
    int m = 0;

    switch_value = (switch_link_t *)value;
    _DEBUG_FILE("%s switch ip(%s)\n", __func__, switch_value->ip);
    ret = get_base_port(switch_value->ip, switch_value->read_key);
    if(ret)
        return;
    for(j = 0; j < count_get_port_type; j++)
    {
        list = g_hash_table_get_values(switch_port_hashtable);
        while(list != NULL)
        {
            switch_port = (switch_port_t *)list->data;
            if(0 == strcasecmp(switch_port->ip, switch_value->ip))
            {
                type_ports_coll[i++] = switch_port->type_port;
            }

            list = g_list_next(list);
        }
        g_list_free(list);
        list = NULL;

        switch_value->type_switch = TYPE_SWITCH_LEAF;
        for(m = 0; m < i; m++)
        {
            if(TYPE_PORT_DOWN == type_ports_coll[m])
            {
                switch_value->type_switch = TYPE_SWITCH_PSEUDO_LEAF;
                break;
            }
        }
        i = 0;
    }
    _DEBUG_FILE("--\n%s switch(%s) type(%d)\n--\n", __func__, switch_value->ip, switch_value->type_switch);

    return;
}

int get_type_of_switch()
{
    g_hash_table_foreach(switch_hashtable, update_switch_type, NULL);

    return SUCCESS;
}

static void update_before_ip_instead_2ls(gpointer key, gpointer value, gpointer user_data)
{
	topo_relation *relation = NULL;
	char switch_ip[MAX_IP_LEN] = {0};
	char before_ip[MAX_IP_LEN] = {0};
	char *switch_before_ip = (char *)user_data;

	sscanf(switch_before_ip, "%s %s", switch_ip, before_ip);

	relation = (topo_relation *)value;
	if(0 == strcmp(relation->pre_ip, switch_ip))
		strcpy(relation->pre_ip, before_ip);
}

static void del_switch_2ls(gpointer key, gpointer value, gpointer user_data)
{
	char *key_ip = (char *)key;
	char *dev_ip = (char *)user_data;

	if(0 == strcmp(key_ip, dev_ip))
	{
		g_hash_table_remove(topo_hashtable, key);
		free(key);
		key = NULL;
		free(value);
		value = NULL;
	}
}

int del_not_exist_2layer_switch()
{
	int i = 0;
	int j = 0;
	int get_flag = 0;
	GList *list = NULL;
	char switch_ip[256][MAX_IP_LEN] = {{0}};
	char before_ip[256][MAX_IP_LEN] = {{0}};
	char switch_before_ip[2*MAX_IP_LEN] = {0};
	topo_relation *info = NULL;

	list = g_hash_table_get_values(topo_hashtable);
	while(list != NULL)
	{
		info = (topo_relation *)list->data;
		if(SWITCH_2LAYER_TYPE == info->dev_type)
		{
			strcpy(switch_ip[i], info->dev_ip);
			strcpy(before_ip[i], info->pre_ip);
			i++;
		}

		list = g_list_next(list);
	}
	g_list_free(list);
	list = NULL;

	for(j = 0; j < i; j++)
	{
		list = g_hash_table_get_values(topo_hashtable);
		while(list != NULL)
		{
			info = (topo_relation *)list->data;
			if(SWITCH_2LAYER_TYPE == info->dev_type
				&& 0 == strcmp(switch_ip[j], info->pre_ip))
				get_flag++;

			list = g_list_next(list);
		}
		g_list_free(list);
		list = NULL;

		if(1 == get_flag)
		{
			g_hash_table_foreach(topo_hashtable, del_switch_2ls, switch_ip[j]);
			sprintf(switch_before_ip, "%s %s", switch_ip[j], before_ip[j]);
			g_hash_table_foreach(topo_hashtable, update_before_ip_instead_2ls, switch_before_ip);
		}

		get_flag = 0;
	}

	return SUCCESS;
}
