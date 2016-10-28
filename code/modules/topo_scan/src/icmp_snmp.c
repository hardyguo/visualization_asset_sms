#include "common.h"

int filter_flag = 0;
struct in_addr subnet_filter_begin_ip[50];
struct in_addr subnet_filter_end_ip[50];

extern topo_config my_config_info;
extern GHashTable *dev_interface_hashtable;
extern GHashTable *dev_route_hashtable;
extern GHashTable *dev_direct_nexthop_hashtable;
extern threadpool tp;
extern int core_mac_num;
extern char flag_core_mac[128][32];

pthread_mutex_t snmp_mutex = PTHREAD_MUTEX_INITIALIZER;

int get_dev_type(char *ip_addr, char *read_key)
{
    int ret = 0;
    snmp_arg arg;
    memset(&arg, 0, sizeof(arg));
    char output[SNMP_RETURN_LEN] = {0};
    int flag_forwarding = 0;
    int flag_bridge_mib = 0;

    assert(NULL != ip_addr);

    arg.peer_name = strdup(ip_addr);
    arg.oid = strdup(OID_IP_FORWARDING);
    arg.community = strdup(read_key);

    /*forwarding*/
    ret = snmp_get(&arg, output, 0);
    if(!ret)
    {
        _DEBUG_FILE("%s get the dev forwarding(%s) of ip(%s) success\n", __func__, output, ip_addr);
        if(SUCCESS == is_digital(output))
        {
            ret = atoi(output);
            if(FORWARDING == ret)
                flag_forwarding = 1;
        }
    }

    /*bridge-mib just for switch*/
    arg.oid = strdup(OID_BASE_NUM_PORTS);
    ret = snmp_get(&arg, NULL, 0);
    if(!ret)
    {
        arg.oid = strdup(OID_STP_ROOT_COST);
        ret = snmp_get(&arg, NULL, 0);
        if(!ret)
        {
            arg.oid = strdup(OID_STP_ROOT_PORT);
            ret = snmp_get(&arg, NULL, 0);
            if(!ret)
            {
				arg.oid = strdup(TP_FDB_PORT);
				ret = snmp_walk(&arg, NULL, 0);
				if(!ret)
					flag_bridge_mib = 1;
				else
				{
					arg.oid = strdup(TP_FDB2_PORT);
					ret = snmp_walk(&arg, NULL, 0);
					if(!ret)
						flag_bridge_mib = 1;
				}
            }
        }
    }

    if(flag_forwarding && flag_bridge_mib)
    {
        return SWITCH_3LAYER_TYPE;
    }
    else if(flag_forwarding)
    {
        return ROUTE_TYPE;
    }
    else if(flag_bridge_mib)
    {
        return SWITCH_2LAYER_SNMP_TYPE;
    }

    /*printer*/
    arg.oid = strdup(OID_PRINTER_RESET);
    ret = snmp_get(&arg, NULL, 0);
    if(!ret)
        return PRINTER_TYPE;

    arg.oid = strdup(OID_PRINTER_GCO);
    ret = snmp_get(&arg, NULL, 0);
    if(!ret)
        return PRINTER_TYPE;

    arg.oid = strdup(OID_PRINTER_GSP);
    ret = snmp_get(&arg, NULL, 0);
    if(!ret)
        return PRINTER_TYPE;

    arg.oid = strdup(OID_PRINTER_CNODL);
    ret = snmp_get(&arg, NULL, 0);
    if(!ret)
        return PRINTER_TYPE;

    arg.oid = strdup(OID_PRINTER_CNODC);
    ret = snmp_get(&arg, NULL, 0);
    if(!ret)
        return PRINTER_TYPE;

    arg.oid = strdup(OID_PRINTER_CD);
    ret = snmp_get(&arg, NULL, 0);
    if(!ret)
        return PRINTER_TYPE;


    return SUCCESS;
}

int next_hop2hash(int scan_layer, char *scan_ip, ip_route_table *my_rt)
{
    int ret = 0;
    int dev_type = 0;
    char tmp_dev_name[SNMP_RETURN_LEN] = {0};
    topo_relation topo_re;
    memset(&topo_re, 0, sizeof(topo_re));
    char read_key_find[128] = {0};

    ret = get_dev_name(my_rt->next_hop, read_key_find, tmp_dev_name, &topo_re.snmp_version);
    if(ret)
    {
        return ret;
    }

    dev_type = get_dev_type(my_rt->next_hop, read_key_find);

    topo_re.topo_layer = scan_layer;
    strcpy(topo_re.dev_name, tmp_dev_name);
    strcpy(topo_re.dev_ip, my_rt->next_hop);
    strcpy(topo_re.dev_mask, my_rt->mask);
    strcpy(topo_re.pre_ip, scan_ip);
    strcpy(topo_re.read_key, read_key_find);
    if(dev_type > 0)
        topo_re.dev_type = dev_type;
    else
        topo_re.dev_type = ROUTE_TYPE;
    ret = store_topo2hash(my_rt->next_hop, &topo_re, NULL);

    return ret;
}

int subnet2hash (int scan_layer, char *scan_ip, ip_route_table *my_rt)
{
    int ret = 0;
    topo_relation topo_re;
    memset(&topo_re, 0, sizeof(topo_relation));

    topo_re.topo_layer = scan_layer;
    strcpy(topo_re.dev_name, "");
    strcpy(topo_re.dev_ip, my_rt->dest);
    strcpy(topo_re.dev_mask, my_rt->mask);
    strcpy(topo_re.pre_ip, scan_ip);
    topo_re.dev_type = SUBNET_TYPE;

    ret = store_topo2hash(my_rt->dest, &topo_re, NULL);
    if (ret)
    {
        _DEBUG_FILE("hash table store subnet ip is %s and ret is %d\n",my_rt->dest, ret);
    }

    return ret;
}

int get_subnet_pool( char *ipadd,char *ipmask, char *subnet_ip1,char *subnet_ip2,char *ipbroadcast)
{
    int ip1,ip2,ip3,ip4=0;
    int ipm1,ipm2,ipm3,ipm4=0;

    if((NULL==ipadd) || (NULL==ipmask) || (NULL==subnet_ip1) ||(NULL==subnet_ip2) || (NULL==ipbroadcast) ) return -1;

    if(!strcmp(ipmask,"255.255.255.0"))
    {
        sscanf(ipadd,"%d.%d.%d.%d",&ip1,&ip2,&ip3,&ip4);
        sprintf(subnet_ip1,"%d.%d.%d.%d",ip1,ip2,ip3,1);
        sprintf(subnet_ip2,"%d.%d.%d.%d",ip1,ip2,ip3,254);
        sprintf(ipbroadcast,"%d.%d.%d.%d",ip1,ip2,ip3,255);
    }
    else
    {
        sscanf(ipadd,"%d.%d.%d.%d",&ip1,&ip2,&ip3,&ip4);
        sscanf(ipmask,"%d.%d.%d.%d",&ipm1,&ipm2,&ipm3,&ipm4);

        sprintf(subnet_ip1,"%d.%d.%d.%d",ip1&ipm1,ip2&ipm2,ip3&ipm3,(ip4&ipm4)+1);   ///begin ip
        sprintf(subnet_ip2,"%d.%d.%d.%d",ip1|(~ipm1&255),ip2|(~ipm2&255),ip3|(~ipm3&255),(ip4|(~ipm4&255))-1); ///end ip
        sprintf(ipbroadcast,"%d.%d.%d.%d",ip1|(~ipm1&255),ip2|(~ipm2&255),ip3|(~ipm3&255),(ip4|(~ipm4&255)));  ///broadcast ip
    }
    return SUCCESS;
}

int ping_host(char *ipadd)
{
    char cmd[128]= {0};
    char output[256]= {0};

    if(ipadd == NULL)
		return ERROR;

    sprintf(cmd, "ping -c 1 -W %d  %s", my_config_info.icmptimeout, ipadd);
    get_sys_cmd_ouput(cmd, output, 256);
    if((strstr(output, ipadd))
		&& (strstr(output,"icmp_seq="))
		&& (strstr(output,"bytes from"))
		&& (strstr(output,"ttl=")))
        return SUCCESS;

    return ERROR;
}

/*
nmap -n -sS -sU -p T:21,22,23,25,53,67,80,110,143,443,1433,1521,3306,5000,5432,8080,50000,U:161 10.0.13.245/24 -T 5

Host is up (0.00086s latency).
PORT      STATE         SERVICE
21/tcp    filtered      ftp
22/tcp    filtered      ssh
23/tcp    filtered      telnet
25/tcp    filtered      smtp
53/tcp    filtered      domain
67/tcp    filtered      dhcps
80/tcp    open          http
110/tcp   filtered      pop3
143/tcp   filtered      imap
443/tcp   open          https
1433/tcp  filtered      ms-sql-s
1521/tcp  filtered      oracle
3306/tcp  open          mysql
5000/tcp  filtered      upnp
5432/tcp  filtered      postgresql
8080/tcp  filtered      http-proxy
50000/tcp filtered      ibm-db2
161/udp   open|filtered snmp

*/
int snmp_host_scan(char * ipadd, char *read_key_find, char *name, service_port_info *sp_info, int *right_snmp_version)
{
    int ret = 0;
    int i = 0;
    int j = 0;
    int m = 0;
    char cmd[256] = {0};
    char output[1024]= {0};
    int nmap_timeout = 0;
    char tmp[128] = {0};
    char *ptr = NULL;
    server_info info[18];
    memset(info, 0, sizeof(info));

    switch(my_config_info.icmptimeout)
    {
    case 1:
        nmap_timeout = 5;
        break;
    case 2:
        nmap_timeout = 4;
        break;
    case 3:
        nmap_timeout = 3;
        break;
    case 4:
        nmap_timeout = 2;
        break;
    case 5:
        nmap_timeout = 1;
        break;
    default:
        nmap_timeout = 0;
        break;
    }

	/*
	ret = ping_host(ipadd);
	if(ret)
		return ERROR;
	*/

    sprintf(cmd, NMAP_SCAN, NMAP_SCAN_TCP_PORT, my_config_info.scan_port, ipadd, nmap_timeout);
    if(get_sys_cmd_ouput(cmd, output, 1024))
    {
        _DEBUG_FILE("%s get sys cmd out error and output is \n%s\n", __func__, output);
    }
    ptr = strcasestr(output, "Host is up");
    if(NULL != ptr)
    {
        for(i=0; i<strlen(ptr); i++)
        {
            if(ptr[i] != '\n')
            {
                tmp[j] = ptr[i];
                j++;
            }
            else
            {
                if(strcasestr(tmp, "/tcp") || strcasestr(tmp, "/udp"))
                {
                    sscanf(tmp, "%s %s %s", info[m].port, info[m].state, info[m].service);
                    m++;
                }
                j = 0;
                memset(tmp, '\0', sizeof(tmp));
            }
        }

		/*161/snmp*/
        strcpy(tmp, info[m-1].state);
        if(strcasestr(tmp, "open"))
        {
			pthread_mutex_lock(&snmp_mutex);
            ret = get_dev_name(ipadd, read_key_find, name, right_snmp_version);
            if(SUCCESS == ret)
            {
                ret = get_dev_type(ipadd, read_key_find);
                if(ret > 0)
                {
					pthread_mutex_unlock(&snmp_mutex);
                    return ret;
                }
            }
			pthread_mutex_unlock(&snmp_mutex);
        }

        for(i=0; i<m-2; i++)
        {
            if(0 == strcasecmp(info[i].state, "open"))
            {
                ret = SERVERS_TYPE;
                break;
            }
        }
    }
    else
        return ERROR;

    if(SERVERS_TYPE == ret)
    {
        i = 0;
        if(0 == strcasecmp(info[i++].state, "open"))
            sp_info->ftp = 1;
        if(0 == strcasecmp(info[i++].state, "open"))
            sp_info->ssh = 1;
        if(0 == strcasecmp(info[i++].state, "open"))
            sp_info->telnet= 1;
        if(0 == strcasecmp(info[i++].state, "open"))
            sp_info->smtp = 1;
        if(0 == strcasecmp(info[i++].state, "open"))
            sp_info->domain= 1;
        if(0 == strcasecmp(info[i++].state, "open"))
            sp_info->dhcps= 1;
        if(0 == strcasecmp(info[i++].state, "open"))
            sp_info->http = 1;
        if(0 == strcasecmp(info[i++].state, "open"))
            sp_info->pop3 = 1;
        if(0 == strcasecmp(info[i++].state, "open"))
            sp_info->imap = 1;
        if(0 == strcasecmp(info[i++].state, "open"))
            sp_info->https = 1;
        if(0 == strcasecmp(info[i++].state, "open"))
            sp_info->ms_sql_s = 1;
        if(0 == strcasecmp(info[i++].state, "open"))
            sp_info->oracle = 1;
        if(0 == strcasecmp(info[i++].state, "open"))
            sp_info->mysql = 1;
        if(0 == strcasecmp(info[i++].state, "open"))
            sp_info->sybase = 1;
        if(0 == strcasecmp(info[i++].state, "open"))
            sp_info->postgresql = 1;
        if(0 == strcasecmp(info[i++].state, "open"))
            sp_info->http_proxy= 1;
        if(0 == strcasecmp(info[i++].state, "open"))
            sp_info->ibm_db2 = 1;
        if(0 == strcasecmp(info[i++].state, "open"))
            sp_info->snmp = 1;

    }
    else
        ret = HOST_TYPE;

    return ret;
}

void threadpool_scan(void *arg)
{
    char ip_addr[64] = {0};
	int ret = 0;
	char cmd[256] = {0};
	char output[1024] = {0};
	char pc_name[128] = {0};
	char pc_mac[18] = {0};

	if(NULL == arg)
	{
		_DEBUG_FILE("[%s] arg NULL!\n", __func__, ip_addr);
		return;
	}
	strcpy(ip_addr, (char *)arg);
	free(arg);
	arg = NULL;

    _DEBUG_INFO("存活性检查IP : %s \n ", ip_addr);
	ret = ping_host(ip_addr);
        printf("ping host %s, ret is %d\n", ip_addr, ret);
	if(ret)
		return;

	bzero(&output, sizeof(output));
    sprintf(cmd, "nbtscan -m -t 2 %s", ip_addr);
    ret = get_sys_cmd_ouput(cmd, output, 1024);
    if(strstr(output, "*timeout"))
    {
		_DEBUG_FILE("[%s] IP:%s\t is down.\n", __func__, ip_addr);
		return;
    }
    else
    {
    	 sscanf(output, "%*s %s %s %*s", pc_name, pc_mac);
		 if(is_invalid_mac(pc_mac))
		 	strcpy(pc_mac, "");

		 /*insert into db*/
		 _DEBUG_FILE("[%s] IP:%s\tMAC:%s\tPC_NAME:%s\n", __func__, ip_addr, pc_mac, pc_name);
        return;
    }

    return;
}

int icmp_scan(char * ipadd_begin, char *ipadd_end, int level, char *mask, char *dst)
{
    int i = 0;
    int addr_count = 0;
    struct in_addr begin_ip;
    struct in_addr end_ip;
    struct in_addr every_ip;
    char tmp_ip[MAX_IP_LEN] = {0};
    topo_relation *myhostinfo = NULL;

    if(is_valid_ipv4_addr(ipadd_begin, &begin_ip))
        return ERROR;
    if(is_valid_ipv4_addr(ipadd_end, &end_ip))
        return ERROR;
    addr_count = ntohl(end_ip.s_addr) - ntohl(begin_ip.s_addr) + 1;
    memcpy(&every_ip, &begin_ip, sizeof(begin_ip));
    for(i = 0; i < addr_count; i++)
    {
        inet_ntop(AF_INET, &every_ip.s_addr, tmp_ip, sizeof(tmp_ip));
        if(g_hash_table_lookup(dev_interface_hashtable, tmp_ip) == NULL)
        {
            myhostinfo = (topo_relation *)malloc(sizeof(topo_relation));
            memset(myhostinfo, 0, sizeof(topo_relation));
            strcpy(myhostinfo->dev_ip, tmp_ip);
            myhostinfo->topo_layer = level;
            strcpy(myhostinfo->dev_mask, mask);
            strcpy(myhostinfo->pre_ip, dst);

            dispatch_threadpool(tp, (void *)threadpool_scan, (void *)myhostinfo);
        }
        every_ip.s_addr += htonl(1);
    }

    clean_threadpool(tp);

    return SUCCESS;
}

int icmp_scan_host(char * ipadd_begin, char *ipadd_end)
{
    int i = 0;
    int addr_count = 0;
    struct in_addr begin_ip;
    struct in_addr end_ip;
    struct in_addr every_ip;
    char *tmp_ip = NULL;

    if(is_valid_ipv4_addr(ipadd_begin, &begin_ip))
        return ERROR;
    if(is_valid_ipv4_addr(ipadd_end, &end_ip))
        return ERROR;
    addr_count = ntohl(end_ip.s_addr) - ntohl(begin_ip.s_addr) + 1;
    memcpy(&every_ip, &begin_ip, sizeof(begin_ip));
    for(i = 0; i < addr_count; i++)
    {
		tmp_ip = (char *)malloc(64);
		memset(tmp_ip, 0, 64);
        inet_ntop(AF_INET, &every_ip.s_addr, tmp_ip, sizeof(tmp_ip));
        dispatch_threadpool(tp, (void *)threadpool_scan, (void *)tmp_ip);
        every_ip.s_addr += htonl(1);
    }
	_DEBUG_FILE("[%s] subnet %s~%s finished.\n", __func__, ipadd_begin, ipadd_end);

    clean_threadpool(tp);

    return SUCCESS;
}

void output_host_info(input_host *input_arg, output_host *host_info)
{
    int ret = 0;
    topo_relation topo_re;
    memset(&topo_re, 0, sizeof(topo_relation));

    if(HOST_UP == host_info->status)
    {
        _DEBUG_FILE("[%s] host_info:%s\t%s\t%d\t%s\t%s\n", __func__, host_info->name?host_info->name:"", host_info->targetipstr, host_info->status, host_info->macascii, host_info->macvendor);
        topo_re.topo_layer = input_arg->scan_layer;
        strcpy(topo_re.dev_name, host_info->name?host_info->name:"");
        strcpy(topo_re.dev_ip, host_info->targetipstr);
        strcpy(topo_re.dev_mask, input_arg->mask);
        strcpy(topo_re.pre_ip, input_arg->scan_ip);
        topo_re.dev_type = HOST_TYPE;

        ret = store_topo2hash(topo_re.dev_ip, &topo_re, NULL);
        if (ret)
        {
            _DEBUG_FILE("hash table store subnet ip is %s and ret is %d\n", topo_re.dev_ip, ret);
        }

        ret = store_hosts2db(input_arg, host_info);
        if (ret)
        {
            _DEBUG_FILE("store host(%s) info to db and ret is %d\n", topo_re.dev_ip, ret);
        }
    }
}

int scan_engine(int scan_layer, ip_route_table *my_rt)
{
    int mask_len;
    char *argv[3];
    char net[64] = {0};
    input_host input_arg;

    memset(&input_arg, 0, sizeof(input_host));
    mask_len = netmask_str2len(my_rt->mask);
    argv[0] = "scan";
    input_arg.argc++;
    argv[1] = "-sn";
    input_arg.argc++;
    sprintf(net, "%s/%d", my_rt->dest, mask_len);
    argv[2] = net;
    input_arg.argc++;
    input_arg.argv = argv;
    input_arg.scan_layer = scan_layer;
    input_arg.scan_ip = my_rt->dest;
    input_arg.mask = my_rt->mask;

    return scan_main(&input_arg, output_host_info);
}

int scan_subnet_host2hash(int scan_layer, char *scan_ip, ip_route_table *my_rt)
{
    int ret = 0;
    char subnet_begin_addr[MAX_IP_LEN] = {0};
    char subnet_end_addr[MAX_IP_LEN] = {0};
    char subnet_broadcast_addr[MAX_IP_LEN] = {0};

    get_subnet_pool(my_rt->dest, my_rt->mask, subnet_begin_addr, subnet_end_addr, subnet_broadcast_addr);
    _DEBUG_INFO("子网%s  扫描, 开始地址  %s  结束地址 %s\n", my_rt->dest, subnet_begin_addr, subnet_end_addr);
    ret = icmp_scan(subnet_begin_addr, subnet_end_addr, scan_layer, my_rt->mask, my_rt->dest);
    if(ret)
    {
        _DEBUG_FILE("%s icmp scan error(ret)\n", __func__, ret);
    }

    return ret;
}

int get_index_by_ip(char *ipadd, int *index, char *read_key)
{
    /*
    IP-MIB::ipAdEntIfIndex.10.0.0.254 = INTEGER: 3718
    IP-MIB::ipAdEntIfIndex.10.0.1.254 = INTEGER: 3846
    */
    int ret = 0;
    char tmp_oid[SNMP_MAXOID] = {0};
    char output[SNMP_RETURN_LEN] = {0};
    snmp_arg arg;
    memset(&arg, 0, sizeof(arg));

    assert(NULL!=ipadd && NULL!=index);

    sprintf(tmp_oid, "%s.%s", OID_IP_IFINDEX, ipadd);
    arg.peer_name = strdup(ipadd);
    arg.oid = strdup(tmp_oid);
    arg.community = strdup(read_key);

    ret = snmp_get(&arg, output, 0);
    if(ret)
    {
        _DEBUG_FILE("%s get ifindex error ret(%d)\n", __func__, ret);
        return ret;
    }
    else
        _DEBUG_FILE("%s get ifindex(%s) success ret(%d)\n", __func__, output, ret);
    if(is_digital(output))
    {
        _DEBUG_FILE("%s get ifindex(%s) is not a digital ret(%d)\n", __func__, output, ret);
        return ERROR;
    }
    *index = atoi(output);

    return SUCCESS;
}

void get_dev_ip_table_callback(snmp_arg *arg, char *ip)
{
    int ret = 0;
    char mask[SNMP_RETURN_LEN] = {0};
    char tmp_oid[SNMP_MAXOID] = {0};
    ip_addr_table mib_ip_table;
    memset(&mib_ip_table, 0, sizeof(ip_addr_table));

    assert(NULL != ip && NULL!=arg);

    if(IS_VALID_IP(ip))
    {
        ret = get_index_by_ip(ip, &mib_ip_table.index, arg->community);
        if(ret)
            return;

        sprintf(tmp_oid, "%s.%s", OID_IP_MASK, ip);
        arg->oid = strdup(tmp_oid);

        /*get the mask*/
        ret = snmp_get(arg, mask, 0);
        if(ret)
        {
            _DEBUG_FILE("%s get mask of ip(%s) error\n", __func__, ip);
        }
        else
        {
            _DEBUG_FILE("%s get mask(%s) of ip(%s) success\n", __func__, mask);
            strcpy(mib_ip_table.mask, mask);
        }

        if(IS_VALID_IP(mib_ip_table.mask))
        {
            ret = store_dev_ip_mask(ip, &mib_ip_table);
            if(ret)
            {
                _DEBUG_FILE("%s get dev mask error\n", __func__);
            }
        }
    }
    return;
}

int get_dev_ip_table(char *ipadd, char *read_key)
{
    int ret = 0;
    int key_flag = 0;
    char *str1, *tmp_read_key, *saveptr;
    snmp_arg arg;
    memset(&arg, 0, sizeof(arg));
    char tmp_rk[128] = {0};

    assert(NULL!=ipadd && NULL!=read_key);

    strcpy(tmp_rk, my_config_info.read_key);
    arg.peer_name = strdup(ipadd);
    arg.oid = strdup(OID_IP_ADDR);

    /*get the ip*/
    for (str1=tmp_rk; ; str1 = NULL)
    {
        tmp_read_key = strtok_r(str1, ",", &saveptr);
        if (tmp_read_key == NULL)
            break;
        arg.community = strdup(tmp_read_key);
        ret = snmp_walk(&arg, get_dev_ip_table_callback, 0);
        if(ret)
        {
            _DEBUG_FILE("%s get the ip mask of ip(%s) error\n", __func__, ipadd);
            continue;
        }
        else
        {
            _DEBUG_FILE("%s get the ip mask of ip(%s) using read key(%s), success\n", __func__, ipadd, arg.community);
            strcpy(read_key, arg.community);
            key_flag = 1;
            break;
        }
    }
    if(0 == key_flag)
    {
        _DEBUG_FILE("%s %s read key error\n", __func__, ipadd);
        return ERROR;
    }

    return SUCCESS;
}

int get_dev_name(char *ipadd, char *read_key, char *devname, int *snmp_version)
{
    int ret = 0;
    int key_flag = 0;
    char *str1, *tmp_read_key, *saveptr;
    char tmp_rk[128] = {0};
    snmp_arg arg;
    memset(&arg, 0, sizeof(arg));

    assert(NULL!=ipadd && NULL!=read_key && NULL!=devname);

    strcpy(tmp_rk, my_config_info.read_key);
    arg.peer_name = strdup(ipadd);
    arg.oid = strdup(OID_SYS_NAME);

    for (str1=tmp_rk; ; str1 = NULL)
    {
        tmp_read_key = strtok_r(str1, ",", &saveptr);
        if (tmp_read_key == NULL)
            break;
        arg.community = strdup(tmp_read_key);
        _DEBUG_FILE("%s the community is (%s).\n", __func__, arg.community);
        ret = snmp_get(&arg, devname, 0);
        if(ret)
        {
            _DEBUG_FILE("%s get the dev name of ip(%s) error\n", __func__, ipadd);
            continue;
        }
        else
        {
            _DEBUG_FILE("%s get the dev name(%s) of ip(%s) success using read key(%s)\n", __func__, devname, ipadd, arg.community);
            strcpy(read_key, arg.community);
            key_flag = 1;
            break;
        }
    }
    if(0 == key_flag)
    {
        _DEBUG_FILE("%s %s read key error\n", __func__, my_config_info.core_ip);
        return ERROR;
    }
	/*get the right snmp version*/
	*snmp_version = arg.version;

    return SUCCESS;

}

void get_dev_route_callback(snmp_arg *arg, char *route_dest)
{
    int ret = 0;
    char output[SNMP_RETURN_LEN] = {0};
    char tmp_oid[SNMP_MAXOID] = {0};
    int type = 0;
    ip_route_table tmp_route_table;
    memset(&tmp_route_table, 0, sizeof(ip_route_table));

    assert(NULL != route_dest);

    sprintf(tmp_oid, "%s.%s", OID_ROUTE_IFINDEX, route_dest);
    arg->oid = strdup(tmp_oid);
    ret = snmp_get(arg, output, 0);
    if(ret)
    {
        _DEBUG_FILE("%s get route route index of ip(%s) error\n", __func__, route_dest);
        return;
    }
    else
        _DEBUG_FILE("%s get route route index(%s) of ip(%s) success\n", __func__, output, route_dest);
    if(is_digital(output))
    {
        _DEBUG_FILE("%s get route index(%s) is not a digital of ip(%s)\n", __func__, output, route_dest);
        return;
    }
    tmp_route_table.index = atoi(output);

    sprintf(tmp_oid, "%s.%s", OID_ROUTE_NEXTHOP, route_dest);
    arg->oid = strdup(tmp_oid);
    ret = snmp_get(arg, output, 0);
    if(ret)
    {
        _DEBUG_FILE("%s get route next hop of ip(%s) error\n", __func__, route_dest);
        return;
    }
    else
        _DEBUG_FILE("%s get route next hop(%s) of ip(%s) success\n", __func__, output, route_dest);
    strncpy(tmp_route_table.next_hop, output, sizeof(tmp_route_table.next_hop));

    if(IS_VALID_IP(tmp_route_table.next_hop))
    {
        sprintf(tmp_oid, "%s.%s", OID_ROUTE_TYPE, route_dest);
        ((snmp_arg*)arg)->oid = strdup(tmp_oid);
        ret = snmp_get((snmp_arg*)arg, output, 0);
        if(ret)
        {
            _DEBUG_FILE("%s get route type of ip(%s) error\n", __func__, route_dest);
            return;
        }
        else
            _DEBUG_FILE("%s get route type(%s) of ip(%s) success\n", __func__, output, route_dest);
        if(is_digital(output))
        {
            _DEBUG_FILE("%s get route type(%s) is not a digital of ip(%s)\n", __func__, output, route_dest);
            return;
        }
        tmp_route_table.type = atoi(output);

        if(DIRECT==tmp_route_table.type || INDIRECT==tmp_route_table.type)
        {
            sprintf(tmp_oid, "%s.%s", OID_ROUTE_MASK, route_dest);
            ((snmp_arg*)arg)->oid = strdup(tmp_oid);
            ret = snmp_get((snmp_arg*)arg, output, 0);
            if(ret)
            {
                _DEBUG_FILE("%s get route mask of ip(%s) error\n", __func__, route_dest);
                return;
            }
            else
                _DEBUG_FILE("%s get route mask(%s) of ip(%s) success\n", __func__, output, route_dest);

            strncpy(tmp_route_table.mask, output, sizeof(tmp_route_table.mask));
            strncpy(tmp_route_table.dest, route_dest, sizeof(tmp_route_table.dest));

            ret = store_route_info(&tmp_route_table);
            if(ret)
            {
                _DEBUG_FILE("%s insert route dest(%s) nexthop(%s) type(%d) mask(%s) error\n", __func__, route_dest, tmp_route_table.next_hop, type, tmp_route_table.mask);
            }
        }
    }

    return;
}

int get_dev_route_table(char *ipadd, char *read_key)
{
    int ret = 0;
    snmp_arg arg;
    memset(&arg, 0, sizeof(arg));

    assert(NULL!=ipadd && NULL!=read_key);

    arg.peer_name = strdup(ipadd);
    arg.oid = strdup(OID_ROUTE_DEST);
    arg.community = strdup(read_key);

    ret = snmp_walk(&arg, get_dev_route_callback, 0);
    if(ret)
    {
        _DEBUG_FILE("%s get dev route error ret(%d)\n", __func__, ret);
        return ret;
    }
    else
        _DEBUG_FILE("%s get dev route success ret(%d)\n", __func__, ret);

    return SUCCESS;
}

int store_core_ip_info()
{
    int ret = 0;
    int dev_type = 0;
    topo_relation topo_re;
    memset(&topo_re, 0, sizeof(topo_re));
    char dev_name[SNMP_RETURN_LEN] = {0};
    char read_key_find[128] = {0};

    ret = get_dev_name(my_config_info.core_ip, read_key_find, dev_name, &topo_re.snmp_version);
    if(ret)
        return ret;

    dev_type = get_dev_type(my_config_info.core_ip, read_key_find);

    topo_re.topo_layer = 0;
    strcpy(topo_re.dev_name, dev_name);
    strcpy(topo_re.dev_ip, my_config_info.core_ip);
    strcpy(topo_re.dev_mask, "");
    strcpy(topo_re.read_key, read_key_find);
    strcpy(topo_re.pre_ip, "");
    if(dev_type > 0)
        topo_re.dev_type = dev_type;
    else
        topo_re.dev_type = DEV_TYPE;

    ret = store_topo2hash(topo_re.dev_ip, &topo_re, NULL);
    if(ret)
    {
        _DEBUG_FILE("%s store dev of ip(%s) to hash error\n", __func__, my_config_info.core_ip);
        return ret;
    }

    return SUCCESS;
}

int get_subnet_filter_range()
{
    char *str1, *tmp_subnet, *saveptr;
    char ip[MAX_IP_LEN] = {0};
    char mask[MAX_IP_LEN] = {0};
    char subnet_begin_addr[MAX_IP_LEN] = {0};
    char subnet_end_addr[MAX_IP_LEN] = {0};
    char subnet_broadcast_addr[MAX_IP_LEN] = {0};
    char tmp_rk[128] = {0};

    assert(NULL!=ip && NULL!=mask);

    if(NULL!=my_config_info.subnetinfo && strcmp("NULL", my_config_info.subnetinfo) && strcmp("", my_config_info.subnetinfo))
    {
        strcpy(tmp_rk, my_config_info.subnetinfo);
        for (str1=tmp_rk; ; str1 = NULL)
        {
            tmp_subnet = strtok_r(str1, ",", &saveptr);
            if (tmp_subnet == NULL)
                break;

            sscanf(tmp_subnet, "%[^/]/%s", ip, mask);
            if(SUCCESS==real_ipaddr(ip) && SUCCESS==real_ipaddr(mask))
            {
                get_subnet_pool(ip, mask, subnet_begin_addr, subnet_end_addr, subnet_broadcast_addr);
				icmp_scan_host(subnet_begin_addr, subnet_end_addr);

                /*if(is_valid_ipv4_addr(subnet_begin_addr, &subnet_filter_begin_ip[filter_flag]))
                    return ERROR;
                if(is_valid_ipv4_addr(subnet_end_addr, &subnet_filter_end_ip[filter_flag]))
                    return ERROR;

                filter_flag++;*/
            }
            else
                return ERROR;
        }
    }

    return SUCCESS;
}

int subnet_filter(char *ip, char *mask)
{
    int i;
    char subnet_begin_addr[MAX_IP_LEN] = {0};
    char subnet_end_addr[MAX_IP_LEN] = {0};
    char subnet_broadcast_addr[MAX_IP_LEN] = {0};
    struct in_addr begin_ip;
    struct in_addr end_ip;

    assert(NULL!=ip && NULL!=mask);

    for(i = 0; i< filter_flag; i++)
    {
        get_subnet_pool(ip, mask, subnet_begin_addr, subnet_end_addr, subnet_broadcast_addr);
        if(is_valid_ipv4_addr(subnet_begin_addr, &begin_ip))
            return ERROR;
        if(is_valid_ipv4_addr(subnet_end_addr, &end_ip))
            return ERROR;

        if(ntohl(begin_ip.s_addr)>=ntohl(subnet_filter_begin_ip[i].s_addr)
                && ntohl(end_ip.s_addr)<=ntohl(subnet_filter_end_ip[i].s_addr))
            return SUCCESS;
    }
    if(filter_flag)
        return ERROR;

    return SUCCESS;
}

int dev_scan(int scan_layer, char *scan_ip)
{
    int ret = 0;
    GList *list_route = NULL;
    ip_route_table *p_route = NULL;;
    ip_route_table tmp_route;
    memset(&tmp_route, 0, sizeof(ip_route_table));
    char read_key_find[128] = {0};

    assert(NULL != scan_ip);
    _DEBUG_FILE("%s scan ip is %s\n", __func__, scan_ip);

    ret = get_dev_ip_table(scan_ip, read_key_find);
    if(ret)
    {
        goto free_hash;
    }

    ret = get_dev_route_table(scan_ip, read_key_find);
    if(ret)
    {
        goto free_hash;
    }

    if(dev_route_hashtable != NULL)
    {
        list_route = g_hash_table_get_values(dev_route_hashtable);
        while(list_route != NULL)
        {
            p_route = (ip_route_table *)list_route->data;
            memcpy(&tmp_route, p_route, sizeof(ip_route_table));

            if(INDIRECT == tmp_route.type)
            {
                if(g_hash_table_lookup(dev_interface_hashtable, tmp_route.next_hop) == NULL
					&& g_hash_table_lookup(dev_direct_nexthop_hashtable, tmp_route.next_hop) == NULL)
                {
                    /*next hop route*/
                    ret = next_hop2hash(scan_layer, scan_ip, &tmp_route);
                    if(ret)
                    {
                        _DEBUG_FILE("%s next hop(%s) to hash error\n", __func__, tmp_route.next_hop);
                    }
                }
            }
            else if(DIRECT == tmp_route.type)
            {
				store_dev_direct_nexthop(tmp_route.next_hop);
                /*subnet*/
                ret = subnet_filter(tmp_route.dest, tmp_route.mask);
                if(SUCCESS == ret)
                {
                    ret = subnet2hash(scan_layer, scan_ip, &tmp_route);
                    if(SUCCESS == ret)
                    {
                        ret = scan_engine(scan_layer, &tmp_route);
                        if(ret)
                        {
                            _DEBUG_FILE("%s subnet(%s) to hash error\n", __func__, tmp_route.dest);
                        }
                    }
                }
                else
                {
                    _DEBUG_FILE("subnet ip(%s) mask(%s) be filter\n", tmp_route.dest, tmp_route.mask);
                }
            }

            list_route = g_list_next(list_route);
        }
        g_list_free(list_route);
        list_route = NULL;
free_hash:
        g_hash_table_remove_all(dev_interface_hashtable);
        g_hash_table_remove_all(dev_route_hashtable);
    }

    return ret;
}

static void get_core_ip_table_callback(snmp_arg *arg, char *ip)
{
    assert(NULL != ip && NULL!=arg);

    if(IS_VALID_IP(ip))
    {
		get_flag_mac_list(ip);
    }

    return;
}

int get_core_ip_table()
{
    int ret = 0;
	int i;
    int key_flag = 0;
    char *str1, *tmp_read_key, *saveptr;
    snmp_arg arg;
    memset(&arg, 0, sizeof(arg));
    char tmp_rk[128] = {0};

    strcpy(tmp_rk, my_config_info.read_key);
    arg.peer_name = strdup(my_config_info.core_ip);
    arg.oid = strdup(OID_IP_ADDR);

    /*get the ip*/
    for (str1=tmp_rk; ; str1 = NULL)
    {
        tmp_read_key = strtok_r(str1, ",", &saveptr);
        if (tmp_read_key == NULL)
            break;
        arg.community = strdup(tmp_read_key);
        ret = snmp_walk(&arg, get_core_ip_table_callback, 0);
        if(ret)
        {
            continue;
        }
        else
        {
            key_flag = 1;
            break;
        }
    }
    if(0 == key_flag)
    {
        return ERROR;
    }

	for(i = 0; i < core_mac_num; i++)
	{
		_DEBUG_FILE("%s %d: %s\n", __func__, i, flag_core_mac[i]);
	}

    return SUCCESS;
}

