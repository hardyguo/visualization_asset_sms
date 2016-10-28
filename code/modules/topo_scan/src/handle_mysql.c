#include "common.h"
#include "queue.h"

MYSQL conn;
msg_queue_t mysql_exe_list;
pthread_mutex_t mysql_mutex = PTHREAD_MUTEX_INITIALIZER;

extern topo_config my_config_info;

/* Convert masklen into IP address's netmask. */
static unsigned long masks[] =
{ 0x0,
	0x80000000, 0xC0000000, 0xE0000000, 0xF0000000,
	0xF8000000, 0xFC000000, 0xFE000000, 0xFF000000,
	0xFF800000, 0xFFC00000, 0xFFE00000, 0xFFF00000,
	0xFFF80000, 0xFFFC0000, 0xFFFE0000, 0xFFFF0000,
	0xFFFF8000, 0xFFFFC000, 0xFFFFE000, 0xFFFFF000,
	0xFFFFF800, 0xFFFFFC00, 0xFFFFFE00, 0xFFFFFF00,
	0xFFFFFF80, 0xFFFFFFC0, 0xFFFFFFE0, 0xFFFFFFF0,
	0xFFFFFFF8, 0xFFFFFFFC, 0xFFFFFFFE, 0xFFFFFFFF
};

int n2mask (struct in_addr *mask, int n)
{
    if (n < 0 || n > 32)
        return -1;
    mask->s_addr = htonl (masks[n]);
    return 0;
}

int init_db()
{
    char server[MAX_IP_LEN] = "127.0.0.1";
    char user[32] = "topo";
    char pwd[32] = "123456";
    char db[32] = "assets_scan_for_test";
    MYSQL *ptr;

    ptr = mysql_init(&conn);
    if(ptr == NULL)
    {
        _DEBUG_FILE("init  mysql object failed!\n");
        return ERROR;
    }
    else
    {
        _DEBUG_FILE("init mysql object successed!\n");
    }
    my_bool reconnect =1;
    mysql_options(&conn,MYSQL_OPT_RECONNECT,&reconnect);
    if(mysql_real_connect(&conn,server,user,pwd,db,0,NULL,CLIENT_MULTI_STATEMENTS))
    {
        mysql_query(&conn,"set names utf8;");
        _DEBUG_FILE("connect successed!\n");
    }
    else
    {
        _DEBUG_FILE("connect failed!\n");
        return ERROR;
    }

    return SUCCESS;
}
int db_close()
{
    mysql_close(&conn);
    return 0;
}

int read_topo_config(topo_config *config)
{
    int ret=0;
    char cmd[256]= {0};
    MYSQL_RES *res_ptr;
    MYSQL_ROW sqlrow;

    sprintf(cmd,"select core_ip,snmp_read_key,layers,snmp_port,icmp_timeout,snmp_timeout,filter_subnet,synchronize_asset,snmp_default_version,max_thread,snmp_retries from topo_config limit 1");
    ret=mysql_query(&conn, cmd);
    if(!ret)
    {
        res_ptr=mysql_store_result(&conn);
        mysql_num_fields(res_ptr);
        if(res_ptr)
        {
            while((sqlrow=mysql_fetch_row(res_ptr)))
            {
                strcpy(config->core_ip,sqlrow[0]);
                strcpy(config->read_key,sqlrow[1]);
                config->scan_layer=atoi(sqlrow[2]);
                config->scan_port=atoi(sqlrow[3]);
                config->icmptimeout=atoi(sqlrow[4]);
                config->snmptimeout=atoi(sqlrow[5]);
                if(sqlrow[6])
                    strcpy(config->subnetinfo,sqlrow[6]);
                else
                    strcpy(config->subnetinfo,"");
                config->asset_transform=atoi(sqlrow[7]);
                if(sqlrow[8])
                    config->snmp_version = atol(sqlrow[8]);
                else
                    config->snmp_version = 0;
                if(sqlrow[9])
                    config->max_thread = atoi(sqlrow[9]);
                else
                    config->max_thread = THREAD_NUM;
                if(sqlrow[10])
                    config->retries = atoi(sqlrow[10]);
                else
                    config->retries = DEFAULT_SNMP_RETIRES;

                _DEBUG_FILE("Get config info  coreip=%s   readkey=%s   level =%d port =%d   icmptm= %d     snmptm= %d \n",
                            config->core_ip,config->read_key,config->scan_layer,config->scan_port,config->icmptimeout,config->snmptimeout);
            }
        }
        mysql_free_result(res_ptr);
        return 0;
    }
    else
    {
        _DEBUG_FILE("query error %d: %s\n",mysql_errno(&conn),  mysql_error(&conn));
        return -1;
    }

}

int clean_links_db()
{
	int ret = 0;
    char cmd[512] = {0};

    sprintf(cmd,"delete from asset_link_resource where discover_type = 0;");
    ret = mysql_query(&conn, cmd);
    if(ret)
    {
	    _DEBUG_FILE("delete ret is %d error!(%s)\n", ret, cmd);
        return ERROR;
    }

	return SUCCESS;
}

int links2db(link_t *info)
{
    int ret = 0;
    char cmd[512] = {0};

    sprintf(cmd,"insert into asset_link_resource(name, link_type, up_device, up_interface, down_device, down_interface, discover_type, link_name) values ('%s', %d, '%s', %d, '%s', %d, %d, '%s');",
		info->name,
		50,//((info->link_type==50)?50:51),
		info->up_ip,
		info->up_port,
		info->down_ip,
		info->down_port,
		0,
		info->name);
    ret = mysql_query(&conn, cmd);
    if(ret)
    {
	    _DEBUG_FILE("insert ret is %d error!(%s)\n", ret, cmd);
        return ERROR;
    }

	return SUCCESS;
}

int topo_relation_store2db(topo_relation *topoNodeinfo)
{
    int ret=0;
    char cmd[512]= {0};
    MYSQL_RES *res_ptr;
    MYSQL_ROW sqlrow;

    sprintf(cmd, "select * from topo_relation where dev_ip='%s'",
            topoNodeinfo->dev_ip);
    ret = mysql_query(&conn, cmd);
    if(!ret)
    {
        res_ptr = mysql_store_result(&conn);
        mysql_num_fields(res_ptr);
        if(res_ptr)
        {
            if((sqlrow = mysql_fetch_row(res_ptr)) > 0)
            {
                mysql_free_result(res_ptr);
                _DEBUG_FILE("topo ip(%s) is exist and return\n", topoNodeinfo->dev_ip);
                return SUCCESS;
            }
        }
        mysql_free_result(res_ptr);
    }
    else
    {
        _DEBUG_FILE("query error %d: %s\n",mysql_errno(&conn), mysql_error(&conn));
        return ERROR;
    }

    sprintf(cmd,"insert into topo_relation (topo_level,dev_name,dev_ip,dev_mask,before_ip,devType_id) values (%d,'%s','%s','%s','%s',%d)",
            topoNodeinfo->topo_layer,
            topoNodeinfo->dev_name,
            topoNodeinfo->dev_ip,
            topoNodeinfo->dev_mask,
            topoNodeinfo->pre_ip,
            topoNodeinfo->dev_type);

    ret = mysql_query(&conn, cmd);
    if(ret)
    {
	    _DEBUG_FILE("insert ret is %d error!(%s)\n", ret, cmd);
        return ERROR;
    }

	return SUCCESS;

}

int get_scan_state()
{
    int ret = 0;
    char cmd[512]= {0};
    MYSQL_RES *res_ptr;
    MYSQL_ROW sqlrow;

    sprintf(cmd, "select scan_result from topo_config limit 1");
    ret = mysql_query(&conn, cmd);
    if(!ret)
    {
        res_ptr = mysql_store_result(&conn);
        if(res_ptr)
        {
            if((sqlrow = mysql_fetch_row(res_ptr)) > 0)
            {
				if(sqlrow[0] && atoi(sqlrow[0]) == TOPOSCANFLAG_BEGIN)
				{
	                mysql_free_result(res_ptr);
	                return ERROR;
				}
            }
        }
        mysql_free_result(res_ptr);
    }
    else
    {
        _DEBUG_FILE("query error %d: %s\n",mysql_errno(&conn), mysql_error(&conn));
        return ERROR;
    }

	return SUCCESS;
}

int set_scan_flag(int flag)
{
    int ret = 0;
    char cmd[512] = {0};

    sprintf(cmd,"update topo_config set scan_result=%d", flag);
    ret=mysql_query(&conn, cmd);
    _DEBUG_FILE("update cmd is %s and ret is %d\n", cmd, ret);
    if(flag == 0)
    {
        /*插入前需要清理原始记录*/
        sprintf(cmd, "delete from topo_relation");
        ret = mysql_query(&conn, cmd);
        _DEBUG_FILE("delete cmd is %s and ret is %d\n", cmd, ret);
    }
    if(!ret)
    {
        return 0;
    }
    else
        return -1;
}

int set_subnet_pool(char *ipadd,char*ipmask,char *ipbegin,char*ipend,char*ipbroadcast)
{
    int ret = 0;
    char cmd[256] = {0};

    sprintf(cmd, "insert into nm_subnet_info (subnet_ip,subnet_mask,begin_ip,end_ip,broad_ip)  select '%s','%s','%s','%s','%s' from dual"\
            " where not exists (select subnet_ip from nm_subnet_info where subnet_ip='%s')",
            ipadd, ipmask, ipbegin, ipend, ipbroadcast, ipadd);
    ret = mysql_query(&conn, cmd);
    if(ret)
    {
        _DEBUG_FILE("%s insert cmd is %s and ret is %d error\n", __func__, cmd, ret);
        return ERROR;
    }

    _DEBUG_FILE("%s insert cmd is %s and ret is %d\n", __func__, cmd, ret);
    return SUCCESS;
}

int subnet_info2db()
{
    int ret = 0;
    char sql_str[256] = {0};
    MYSQL_RES *res_ptr;
    MYSQL_ROW sqlrow;
    char ip_addr[MAX_IP_LEN] = {0};
    char mask[MAX_IP_LEN] = {0};
    char subnet_begin_addr[MAX_IP_LEN] = {0};
    char subnet_end_addr[MAX_IP_LEN] = {0};
    char subnet_broadcast_addr[MAX_IP_LEN] = {0};

    sprintf(sql_str, "select distinct(dev_ip),dev_mask from topo_relation where devType_id=%d", SWITCH_2LAYER_TYPE);
    ret = mysql_query(&conn, sql_str);
    if(!ret)
    {
        res_ptr = mysql_store_result(&conn);
        mysql_num_fields(res_ptr);
        if(res_ptr)
        {
            while((sqlrow = mysql_fetch_row(res_ptr)))
            {
                if(sqlrow[0])
                    strcpy(ip_addr, sqlrow[0]);
                else
                    continue;
                if(sqlrow[1])
                    strcpy(mask, sqlrow[1]);
                else
                    continue;
                ret = get_subnet_pool(ip_addr, mask, subnet_begin_addr, subnet_end_addr, subnet_broadcast_addr);
                if(ret)
                {
                    _DEBUG_FILE("%s get subnet pool(%s) error\n", __func__, ip_addr);
                    continue;
                }
                ret = set_subnet_pool(ip_addr, mask, subnet_begin_addr, subnet_end_addr, subnet_broadcast_addr);
                if(ret)
                {
                    _DEBUG_FILE("%s set subnet pool(%s) error\n", __func__, ip_addr);
                    continue;
                }
            }
        }
        mysql_free_result(res_ptr);
        return SUCCESS;
    }
    else
    {
        _DEBUG_FILE("%s query error %d: %s\n", __func__, mysql_errno(&conn), mysql_error(&conn));
        return ERROR;
    }
}

int get_self_ip(char *core_ip, char *self_ip)
{
    int ret = 0;
    char sql_str[256] = {0};
    MYSQL_RES *res_ptr;
    MYSQL_ROW sqlrow;
    char ip_mask[MAX_IP_LEN] = {0};
    char ip_addr[MAX_IP_LEN] = {0};
    int mask = 0;
    struct in_addr in_core_ip;
    struct in_addr in_ip;
    struct in_addr in_mask;

    strcpy(sql_str, "select ipaddrmask from sys_interface;");
    ret = mysql_query(&conn, sql_str);
    if(!ret)
    {
        res_ptr = mysql_store_result(&conn);
        if(res_ptr)
        {
            while((sqlrow = mysql_fetch_row(res_ptr)))
            {
                if(sqlrow[0])
                {
                    strcpy(ip_mask, sqlrow[0]);
                    sscanf(ip_mask, "%[^/]/%d", ip_addr, &mask);

                    if(is_valid_ipv4_addr(ip_addr, &in_core_ip))
                        continue;
                    if(is_valid_ipv4_addr(core_ip, &in_ip))
                        continue;

                    n2mask(&in_mask, mask);
                    if(same_subnet(&in_core_ip, &in_ip, &in_mask))
                    {
                        strcpy(self_ip, ip_addr);
                        break;
                    }

                }
            }
            mysql_free_result(res_ptr);
            return SUCCESS;
        }
        else
        {
            _DEBUG_FILE("%s query error %d: %s\n", __func__, mysql_errno(&conn), mysql_error(&conn));
            return ERROR;
        }
    }
    return ERROR;
}

void exec_sql(char *cmd)
{
    char *data = NULL;

    if(cmd == NULL)
        return;

    data = (char*)malloc(SQL_LEN);
    if(data == NULL)
    {
        _DEBUG_FILE("[%s] malloc error!\n", __func__);
        return;
    }
    memset(data, 0, SQL_LEN);
    strcpy(data, cmd);
    pthread_mutex_lock(&mysql_mutex);
    en_queue(&mysql_exe_list, data);
    pthread_mutex_unlock(&mysql_mutex);
}

int store_hosts2db(input_host *input_arg, output_host *host_info)
{
    char sql_cmd[SQL_LEN] = {0};

    sprintf(sql_cmd, "insert into asset (name, ip, mask, macascii, macvendor)"
        " values (%s, '%s', '%s', %s, %s);",
        host_info->name,
        host_info->targetipstr,
        input_arg->mask,
        host_info->macascii,
        host_info->macvendor);

    exec_sql(sql_cmd);

    return SUCCESS;
}

void *mysql_process()
{
    int ret = 0;
    MYSQL_RES * result = NULL;
    void *queue_data = NULL;
    char sql_cmd[SQL_LEN] = {0};

    while(1)
    {
        pthread_mutex_lock(&mysql_mutex);
        queue_data = out_queue(&mysql_exe_list);
        pthread_mutex_unlock(&mysql_mutex);
        if(queue_data)
        {
            memset(sql_cmd, 0, SQL_LEN);
            strncpy(sql_cmd, queue_data, SQL_LEN);
            free(queue_data);
            queue_data = NULL;
            if(strlen(sql_cmd)>1)
            {
                mysql_query(&conn, "set names utf8");
                ret = mysql_query(&conn, sql_cmd);
                do
                {
                    result = mysql_store_result(&conn);
                    mysql_free_result(result);
                }
                while (!mysql_next_result(&conn));
                if(ret)
                {
                    _DEBUG_FILE("[%s] exe sql error !conn:%d errno:%d errinfo:%s cmd:%s\n",
                           __func__,
                           &conn,
                           mysql_errno(&conn),
                           mysql_error(&conn),
                           sql_cmd);
                }
            }
        }
        else
            usleep(10);
    }
}

