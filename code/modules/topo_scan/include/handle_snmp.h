#ifndef __MYSNMP_H__
#define __MYSNMP_H__

typedef struct _snmp_arg
{
    char *peer_name;
    char *oid;
    char *community;
	int version;
	
} snmp_arg;

typedef void (*snmp_walk_callback)(snmp_arg *, char *); 

/*
 * snmp_arg                --input parameter for transmit
 * snmp_walk_callback      --output paramter for callback function
 * int                     --input parameter for setting return value
 */
int snmp_walk(snmp_arg *, snmp_walk_callback, int);
/*
 * snmp_arg                --input parameter for transmit
 * char                    --output paramter for return value
 * int                     --input parameter for setting return value
 */
int snmp_get(snmp_arg *, char *, int);

#endif