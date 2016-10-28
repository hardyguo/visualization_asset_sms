#include <ctype.h>
#include <iconv.h>
#include "common.h"

extern char scan_info_path[128];
extern int debug_mode;

int get_sys_cmd_ouput(const char*cmd,char*output,int len)
{
    if(cmd==NULL) return -1;
    FILE*ptr=NULL;
    char tmp[256]= {0};
    sprintf(tmp,"%s    2>/dev/null   ",cmd);
    if((ptr = popen(tmp,"r"))!= NULL)
    {
        fread(output,len,1,ptr);
        pclose(ptr);
    }
    else
    {
        return -1;
    }
    return SUCCESS;
}

int is_valid_ipv4_addr(char *str_ip, struct in_addr *addr)
{
    int ret;

    assert(str_ip != NULL && addr != NULL);
    ret = inet_pton(AF_INET, str_ip, &(addr->s_addr));
    if(ret <= 0)
    {
        return ERROR;
    }

    if(addr->s_addr == 0)
    {
        return ERROR;
    }
    else
        return SUCCESS;
}

#define mac_len 17
#define mac_row 6
#define mac_col 2
int is_invalid_mac(const char*mac)
{
    int ret = 0;
    int i,j;
    char tmp;
    char buf[mac_row][mac_col] = {{0},{0}};

    if(strlen(mac) != mac_len)
        return ERROR;
    if((ret = sscanf(mac, "%[^:]:%[^:]:%[^:]:%[^:]:%[^:]:%[^:]",buf[0],buf[1],buf[2],buf[3],buf[4],buf[5])) != 6)
        return ERROR;
    for( i=0; i<mac_row; i++)
    {
        for( j=0; j<mac_col; j++)
        {
            tmp = toupper(buf[i][j]);
            if(tmp < '0' || tmp > 'F' || (tmp > '9' && tmp < 'A'))
                return ERROR;
        }
    }
    return SUCCESS;
}

int is_digital(const char *value)
{
    if (NULL == value)
        return ERR_NULL_PARAMETER;

    const char *tmp = value;
    for (; *tmp!='\0' && *tmp!='\n'; tmp++)
    {
        if (*tmp < '0' || *tmp > '9')
        {
            return ERROR;
        }
    }

    return SUCCESS;;
}

int real_ipaddr(char *ipadd)
{
    int ip1=300,  ip2=300,  ip3=300,  ip4=300;

    if(ipadd==NULL) return -1;
    sscanf(ipadd,"%d.%d.%d.%d",&ip1,&ip2,&ip3,&ip4);
    if(  ((ip1<=255) &&(ip1>0)) && ((ip2<=255) && (ip2>=0)) && ((ip3<=255) && (ip3>=0)) && ((ip4<=255) && (ip4>=0)))  return 0;
    else
        return -1;

}

void _DEBUG_FILE(char *fmt, ...)
{
    /*
    FILE *fp_debug=NULL;
    struct stat     f_stat;
    char tmp[256]= {0};

    fp_debug=fopen(LOG_TOPO,"a+");
    if(fp_debug==NULL)	return ;
    va_list argp;
    va_start(argp, fmt);
    vfprintf(fp_debug, fmt, argp);
    if(debug_mode)
        vfprintf(stdout, fmt, argp);
    va_end(argp);
    fclose(fp_debug);

    if (stat(LOG_TOPO, &f_stat) == -1)
    {
        return;
    }
    if(f_stat.st_size>1500000)
    {
        sprintf(tmp, "rm -rf  %s", LOG_TOPO);
        system(tmp);
    }
    */

    char szMessage[1024] = {0};
    va_list pArg;
    va_start(pArg, fmt);
    vsnprintf(szMessage, 1023, fmt, pArg);
    va_end(pArg);

    time_t nNowTime = time(NULL);
    struct tm *pDate = localtime(&nNowTime);
    if (pDate==NULL)
        return;

    int nYear = 1900 + pDate->tm_year;
    int nMonth = pDate->tm_mon+1;
    int nDay = pDate->tm_mday;
    int nHour = pDate->tm_hour;
    int nMin  = pDate->tm_min;
    int nSec  = pDate->tm_sec;

    FILE* pLoger = fopen(LOG_TOPO, "a+");
    if (pLoger == NULL) return;

    fprintf(pLoger, "[%d%02d%02d %02d:%02d:%02d] %s", nYear, nMonth, nDay, nHour, nMin, nSec, szMessage);
    fclose(pLoger);

    if(debug_mode)
        fprintf(stdout, "[%d%02d%02d %02d:%02d:%02d] %s", nYear, nMonth, nDay, nHour, nMin, nSec, szMessage);
}



int code_convert(char *from_charset,char *to_charset,char *inbuf,
                 int inlen,char *outbuf,int outlen)
{
    iconv_t cd;
    char **pin = &inbuf;
    char **pout = &outbuf;
    cd = iconv_open(to_charset,from_charset);
    if (cd==0)
    {
        return -1;
    }
    memset(outbuf,0,outlen);
    if (iconv(cd,pin,(size_t *)&inlen,pout,(size_t *)&outlen)==-1)
    {
        iconv_close(cd);
        return -1;
    }
    iconv_close(cd);
    return 0;
}

int g2u(char *inbuf,size_t inlen,char *outbuf,size_t outlen)
{
    return code_convert("gb2312","utf-8",inbuf,inlen,outbuf,outlen);
}

void _DEBUG_INFO(char *fmt, ...)
{
    FILE *fp_debug=NULL;
    struct stat     f_stat;
    char tmp[256]= {0};
    char outstr[1024]= {0};

    fp_debug=fopen(scan_info_path,"a+");
    if(fp_debug==NULL)	return ;
    va_list argp;
    va_start(argp, fmt);
    //g2u(fmt,strlen(fmt),outstr,1024);
    vfprintf(fp_debug, outstr, argp);
    va_end(argp);
    fclose(fp_debug);

    if (stat(scan_info_path, &f_stat) == -1)
    {
        return;
    }
    if(f_stat.st_size>500000)
    {
        sprintf(tmp,"rm -rf  %s",scan_info_path);
        system(tmp);
    }
}

void signal_pro()
{
    _DEBUG_FILE("now soc_scan is exit ~!~\n");
    exit(0);
}

int signal_init()
{
    signal(SIGINT, signal_pro);
    signal(SIGTERM, signal_pro);
    signal(SIGHUP, signal_pro);
    signal(SIGQUIT, signal_pro);

    return SUCCESS;
}

int same_subnet(struct in_addr *first, struct in_addr *second, struct in_addr *mask)
{
	return (ntohl(first->s_addr) & ntohl(mask->s_addr)) ==
			(ntohl(second->s_addr) & ntohl(mask->s_addr));
}

/*
 * len --> *.*.*.*
 * 25 --> 255.255.255.128
 */
char* netmask_len2str(int mask_len, char* mask_str)
{
    int i;
    int i_mask;

    for (i = 1, i_mask = 1; i < mask_len; i++)
    {
        i_mask = (i_mask << 1) | 1;
    }

    i_mask = htonl(i_mask << (32 - mask_len));
    strcpy(mask_str, inet_ntoa(*((struct in_addr *)&i_mask)));

    return mask_str;
}

/*
 * *.*.*.* --> len
 * 255.255.255.128 --> 25
 */
int netmask_str2len(char* mask)
{
    int netmask = 0;
    unsigned int mask_tmp;

    mask_tmp = ntohl((int)inet_addr(mask));
    while (mask_tmp & 0x80000000)
    {
        netmask++;
        mask_tmp = (mask_tmp << 1);
    }

    return netmask;
}

