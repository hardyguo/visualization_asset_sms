#ifndef MAIN_H
#define MAIN_H

#define HOST_UNKNOWN 0
#define HOST_UP 1
#define HOST_DOWN 2

/*
 * arg for input
 */
typedef struct _input_host
{
    int argc;       //for nmap
    char **argv;   //for nmap
    int scan_layer;
    char *scan_ip;
    char *mask;

} input_host;

/*
 * arg for output
 */
typedef struct _output_host
{
    const char *name;
    const char *targetipstr;
    unsigned int status;
    char macascii[32];
    const char *macvendor;

} output_host;

typedef void (*scan_callback)(input_host *, output_host *);
/*
 * int                     --input parameter for transmit
 * char *[]                --input parameter for transmit
 * scan_callback           --output paramter for callback function
 */
#ifdef __cplusplus
extern "C" {
#endif
int scan_main(input_host *, scan_callback);
#ifdef __cplusplus
}
#endif

#endif /* MAIN_H */

