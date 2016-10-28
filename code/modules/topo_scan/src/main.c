#include "common.h"

topo_config my_config_info;
threadpool tp;
char scan_info_path[128];
int debug_mode = 0;
#define SCAN_VERSION "1.1"

void usage()
{
    debug_mode = 1;
    _DEBUG_FILE("Usage:\n\ntopo_scan [-d <debug>]\n\n"\
                "version %s time %s %s\n", SCAN_VERSION, __TIME__, __DATE__);
    exit(0);
}

int init_thread()
{
    int ret = 0;

    ret = dispatch_threadpool(tp, (void *)mysql_process, NULL);
    if(ret)
        goto err;
    else
        return SUCCESS;

    err:
    _DEBUG_FILE("init thread error!");
    return ERROR;
}

int main (int argc, char **argv)
{
    int ret = 0;
    int i = 0;
    int j = 0;
    int scan_count = 0;
    int scan_layer = 0;
    char scan_ipadd[1024][MAX_IP_LEN] = {{0}};
    char pidstr[128] = {0};

    if(access(LOG_DIR, F_OK))
        mkdir(LOG_DIR, 0777);

    if(argc > 1 && NULL != argv[1])
    {
        if(strstr(argv[1], "-d"))
            debug_mode = 1;
		else
			usage();
    }
    else
        printf("add '-d' to debug mode\n");

    sprintf(scan_info_path, "%s", LOG_FILE_INFO);
    if(remove(scan_info_path))
        _DEBUG_FILE("remove %s error! \n", scan_info_path);
    sprintf(pidstr, "rm -rf %s;echo %d > /tmp/topo_pidfile \n ", scan_info_path, getpid());
    system(pidstr);

    ret = signal_init();
    if(ret)
        return ret;

    ret = create_hash_table();
    if(ret)
    {
        _DEBUG_FILE("Create hash table error! \n");
        return ret;
    }

    ret = init_db();
    if(ret)
        return ret;

    /*
    ret = init_time_check_socket();
    if(ret)
        return ret;
    */

    memset(&my_config_info, 0, sizeof(topo_config));
    ret = read_topo_config(&my_config_info);
    if(ret)
        return ret;

    /*snmp version*/
    switch(my_config_info.snmp_version)
    {
    case 1:
        my_config_info.snmp_version = SNMP_VERSION_1;
        break;
    case 3:
        my_config_info.snmp_version = SNMP_VERSION_3;
        break;
    default:
        my_config_info.snmp_version = SNMP_VERSION_2c;
        break;
    }

    tp = create_threadpool(my_config_info.max_thread);
    if(tp == NULL)
        return ERROR;

    ret = init_thread();
    if(ret)
        return ret;

    ret = get_subnet_filter_range();
    if(ret)
    {
        _DEBUG_FILE("get subnet filter range error\n");
        return ret;
    }

	ret = get_scan_state();
	if(ret)
	{
		_DEBUG_FILE("A scan have been running, so exit!\n");
		return ret;
	}

    /*san begin ********************************************************************************************/
    ret = set_scan_flag(TOPOSCANFLAG_BEGIN);
    if(ret)
        return ret;
    _DEBUG_INFO("topo discover begin......\n ");

    for(i=1; i<=my_config_info.scan_layer; i++)
    {
        if(i == 1)
        {
            _DEBUG_INFO("begin level 1.\n",i);
            ret = store_core_ip_info();
            if(ret)
            {
                _DEBUG_FILE("store core ip info error\n");
                goto finish;
            }
            ret = dev_scan(1, my_config_info.core_ip);
            if(ret)
            {
                _DEBUG_FILE("dev scan error on level %d\n", i);
            }
        }
        else
        {
            scan_layer = i - 1;
            _DEBUG_INFO("begin level %d.\n", i);
            _DEBUG_FILE("now  scan  %d  level info...\n",i);
            scan_count = get_scan_dev(scan_layer, scan_ipadd);
            for(j=0; j<scan_count; j++)
            {
                if(strlen(scan_ipadd[j]) < 1)
                    continue;
                _DEBUG_INFO("need to be scanned ip is: %s\n",scan_ipadd[j]);
                ret = dev_scan(scan_layer+1, scan_ipadd[j]);
                if(ret)
                {
                    _DEBUG_FILE("dev scan error on level %d\n", i);
                }
            }
        }

    }
    destroy_threadpool(tp);

	get_switch_link();

    topo_hash_info_show();

	clean_links_db();
	link_hash_info_show();
finish:
    ret = set_scan_flag(TOPOSCANFLAG_END);
    _DEBUG_INFO("topo discover end.\n ");
    /*san end ********************************************************************************************/
    subnet_info2db();

    free_all_hash_table();
    close_time_check_socket();
    db_close();
    _DEBUG_FILE("TOPO DATA SCAN COMPLETE  !!! \n");

    return 0;
}

