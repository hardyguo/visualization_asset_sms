#include <net-snmp/net-snmp-config.h>

#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#include <sys/types.h>
#if HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#if TIME_WITH_SYS_TIME
# ifdef WIN32
#  include <sys/timeb.h>
# else
#  include <sys/time.h>
# endif
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif
#if HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#include <stdio.h>
#if HAVE_WINSOCK_H
#include <winsock.h>
#endif
#if HAVE_NETDB_H
#include <netdb.h>
#endif
#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include <net-snmp/net-snmp-includes.h>
#include <ctype.h>
#include "handle_snmp.h"
#include "common.h"

extern topo_config my_config_info;
extern void _DEBUG_FILE(char *fmt, ...);

#define NETSNMP_DS_APP_DONT_FIX_PDUS 0
#define NETSNMP_DS_WALK_INCLUDE_REQUESTED	        1
#define NETSNMP_DS_WALK_PRINT_STATISTICS	        2
#define NETSNMP_DS_WALK_DONT_CHECK_LEXICOGRAPHIC	3
#define NETSNMP_DS_WALK_TIME_RESULTS     	        4
#define NETSNMP_DS_WALK_DONT_GET_REQUESTED	        5

oid             objid_mib[] = { 1, 3, 6, 1, 2, 1 };
int             numprinted = 0;

/*mibs*/

int
sprint_realloc_badtype_my(u_char ** buf, size_t * buf_len, size_t * out_len,
                          int allow_realloc,
                          const netsnmp_variable_list * var,
                          const struct enum_list *enums,
                          const char *hint, const char *units)
{
    u_char          str[] = "Variable has bad type";

    return snmp_strcat(buf, buf_len, out_len, allow_realloc, str);
}

int
sprint_realloc_integer_my(u_char ** buf, size_t * buf_len, size_t * out_len,
                          int allow_realloc,
                          const netsnmp_variable_list * var,
                          const struct enum_list *enums,
                          const char *hint, const char *units)
{
    char           *enum_string = NULL;

    if ((var->type != ASN_INTEGER) &&
            (!netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICKE_PRINT)))
    {
        u_char          str[] = "Wrong Type (should be INTEGER): ";
        if (snmp_strcat(buf, buf_len, out_len, allow_realloc, str))
        {
            return sprint_realloc_by_type(buf, buf_len, out_len,
                                          allow_realloc, var, NULL, NULL,
                                          NULL);
        }
        else
        {
            return 0;
        }
    }
    for (; enums; enums = enums->next)
    {
        if (enums->value == *var->val.integer)
        {
            enum_string = enums->label;
            break;
        }
    }

    if (!netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICK_PRINT))
    {
        if (!snmp_strcat(buf, buf_len, out_len, allow_realloc,
                         (const u_char *) ""))
        {
            //(const u_char *) "INTEGER: ")) {
            return 0;
        }
    }

    if (enum_string == NULL ||
            netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_PRINT_NUMERIC_ENUM))
    {
        if (hint)
        {
            if (!(sprint_realloc_hinted_integer(buf, buf_len, out_len,
                                                allow_realloc,
                                                *var->val.integer, 'd',
                                                hint, units)))
            {
                return 0;
            }
        }
        else
        {
            char            str[16];
            sprintf(str, "%ld", *var->val.integer);
            if (!snmp_strcat
                    (buf, buf_len, out_len, allow_realloc,
                     (const u_char *) str))
            {
                return 0;
            }
        }
    }
    else if (netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICK_PRINT))
    {
        if (!snmp_strcat
                (buf, buf_len, out_len, allow_realloc,
                 (const u_char *) enum_string))
        {
            return 0;
        }
    }
    else
    {
        char            str[16];
        sprintf(str, "(%ld)", *var->val.integer);
        if (!snmp_strcat
                (buf, buf_len, out_len, allow_realloc,
                 (const u_char *) enum_string))
        {
            return 0;
        }
        if (!snmp_strcat
                (buf, buf_len, out_len, allow_realloc, (const u_char *) str))
        {
            return 0;
        }
    }

    if (units)
    {
        return (snmp_strcat
                (buf, buf_len, out_len, allow_realloc,
                 (const u_char *) " ")
                && snmp_strcat(buf, buf_len, out_len, allow_realloc,
                               (const u_char *) units));
    }
    return 1;
}

int
sprint_realloc_octet_string_my(u_char ** buf, size_t * buf_len,
                               size_t * out_len, int allow_realloc,
                               const netsnmp_variable_list * var,
                               const struct enum_list *enums, const char *hint,
                               const char *units)
{
    size_t          saved_out_len = *out_len;
    const char     *saved_hint = hint;
    int             hex = 0, x = 0;
    u_char         *cp;
    int             output_format, len_needed;

    if ((var->type != ASN_OCTET_STR) &&
            (!netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICKE_PRINT)))
    {
        const char      str[] = "Wrong Type (should be OCTET STRING): ";
        if (snmp_cstrcat
                (buf, buf_len, out_len, allow_realloc, str))
        {
            return sprint_realloc_by_type(buf, buf_len, out_len,
                                          allow_realloc, var, NULL, NULL,
                                          NULL);
        }
        else
        {
            return 0;
        }
    }


    if (hint)
    {
        int             repeat, width = 1;
        long            value;
        char            code = 'd', separ = 0, term = 0, ch, intbuf[16];
        u_char         *ecp;

        if (!netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICK_PRINT))
        {
            if (!snmp_cstrcat(buf, buf_len, out_len, allow_realloc, ""))
            {
                //if (!snmp_cstrcat(buf, buf_len, out_len, allow_realloc, "STRING: ")) {
                return 0;
            }
        }
        cp = var->val.string;
        ecp = cp + var->val_len;

        while (cp < ecp)
        {
            repeat = 1;
            if (*hint)
            {
                if (*hint == '*')
                {
                    repeat = *cp++;
                    hint++;
                }
                width = 0;
                while ('0' <= *hint && *hint <= '9')
                    width = (width * 10) + (*hint++ - '0');
                code = *hint++;
                if ((ch = *hint) && ch != '*' && (ch < '0' || ch > '9')
                        && (width != 0
                            || (ch != 'x' && ch != 'd' && ch != 'o')))
                    separ = *hint++;
                else
                    separ = 0;
                if ((ch = *hint) && ch != '*' && (ch < '0' || ch > '9')
                        && (width != 0
                            || (ch != 'x' && ch != 'd' && ch != 'o')))
                    term = *hint++;
                else
                    term = 0;
                if (width == 0)  /* Handle malformed hint strings */
                    width = 1;
            }

            while (repeat && cp < ecp)
            {
                value = 0;
                if (code != 'a' && code != 't')
                {
                    for (x = 0; x < width; x++)
                    {
                        value = value * 256 + *cp++;
                    }
                }
                switch (code)
                {
                case 'x':
                    if (netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID,
                                               NETSNMP_DS_LIB_2DIGIT_HEX_OUTPUT)
                            && value < 16)
                    {
                        sprintf(intbuf, "0%lx", value);
                    }
                    else
                    {
                        sprintf(intbuf, "%lx", value);
                    }
                    if (!snmp_cstrcat
                            (buf, buf_len, out_len, allow_realloc, intbuf))
                    {
                        return 0;
                    }
                    break;
                case 'd':
                    sprintf(intbuf, "%ld", value);
                    if (!snmp_cstrcat
                            (buf, buf_len, out_len, allow_realloc, intbuf))
                    {
                        return 0;
                    }
                    break;
                case 'o':
                    sprintf(intbuf, "%lo", value);
                    if (!snmp_cstrcat
                            (buf, buf_len, out_len, allow_realloc, intbuf))
                    {
                        return 0;
                    }
                    break;
                case 't': /* new in rfc 3411 */
                case 'a':
                    /* A string hint gives the max size - we may not need this much */
                    len_needed = SNMP_MIN( width, ecp-cp );
                    while ((*out_len + len_needed + 1) >= *buf_len)
                    {
                        if (!(allow_realloc && snmp_realloc(buf, buf_len)))
                        {
                            return 0;
                        }
                    }
                    for (x = 0; x < width && cp < ecp; x++)
                    {
                        *(*buf + *out_len) = *cp++;
                        (*out_len)++;
                    }
                    *(*buf + *out_len) = '\0';
                    break;
                default:
                    *out_len = saved_out_len;
                    if (snmp_cstrcat(buf, buf_len, out_len, allow_realloc,
                                     "(Bad hint ignored: ")
                            && snmp_cstrcat(buf, buf_len, out_len,
                                            allow_realloc, saved_hint)
                            && snmp_cstrcat(buf, buf_len, out_len,
                                            allow_realloc, ") "))
                    {
                        return sprint_realloc_octet_string_my(buf, buf_len,
                                                              out_len,
                                                              allow_realloc,
                                                              var, enums,
                                                              NULL, NULL);
                    }
                    else
                    {
                        return 0;
                    }
                }

                if (cp < ecp && separ)
                {
                    while ((*out_len + 1) >= *buf_len)
                    {
                        if (!(allow_realloc && snmp_realloc(buf, buf_len)))
                        {
                            return 0;
                        }
                    }
                    *(*buf + *out_len) = separ;
                    (*out_len)++;
                    *(*buf + *out_len) = '\0';
                }
                repeat--;
            }

            if (term && cp < ecp)
            {
                while ((*out_len + 1) >= *buf_len)
                {
                    if (!(allow_realloc && snmp_realloc(buf, buf_len)))
                    {
                        return 0;
                    }
                }
                *(*buf + *out_len) = term;
                (*out_len)++;
                *(*buf + *out_len) = '\0';
            }
        }

        if (units)
        {
            return (snmp_cstrcat
                    (buf, buf_len, out_len, allow_realloc, " ")
                    && snmp_cstrcat(buf, buf_len, out_len, allow_realloc, units));
        }
        if ((*out_len >= *buf_len) &&
                !(allow_realloc && snmp_realloc(buf, buf_len)))
        {
            return 0;
        }
        *(*buf + *out_len) = '\0';

        return 1;
    }

    output_format = netsnmp_ds_get_int(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_STRING_OUTPUT_FORMAT);
    if (0 == output_format)
    {
        output_format = NETSNMP_STRING_OUTPUT_GUESS;
    }
    switch (output_format)
    {
    case NETSNMP_STRING_OUTPUT_GUESS:
        hex = 0;
        for (cp = var->val.string, x = 0; x < (int) var->val_len; x++, cp++)
        {
            if (!isprint(*cp) && !isspace(*cp))
            {
                hex = 1;
            }
        }
        break;

    case NETSNMP_STRING_OUTPUT_ASCII:
        hex = 0;
        break;

    case NETSNMP_STRING_OUTPUT_HEX:
        hex = 1;
        break;
    }

    if (var->val_len == 0)
    {
        return snmp_cstrcat(buf, buf_len, out_len, allow_realloc, "\"\"");
    }

    if (hex)
    {
        if (netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICK_PRINT))
        {
            if (!snmp_cstrcat(buf, buf_len, out_len, allow_realloc, ""))
            {
                //if (!snmp_cstrcat(buf, buf_len, out_len, allow_realloc, "\"")) {
                return 0;
            }
        }
        else
        {
            if (!snmp_cstrcat
                    (buf, buf_len, out_len, allow_realloc, ""))
            {
                //(buf, buf_len, out_len, allow_realloc, "Hex-STRING: ")) {
                return 0;
            }
        }

        if (!sprint_realloc_hexstring(buf, buf_len, out_len, allow_realloc,
                                      var->val.string, var->val_len))
        {
            return 0;
        }

        if (netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICK_PRINT))
        {
            if (!snmp_cstrcat(buf, buf_len, out_len, allow_realloc, ""))
            {
                //if (!snmp_cstrcat(buf, buf_len, out_len, allow_realloc, "\"")) {
                return 0;
            }
        }
    }
    else
    {
        if (!netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICK_PRINT))
        {
            if (!snmp_cstrcat(buf, buf_len, out_len, allow_realloc,
                              ""))
            {
                //"STRING: ")) {
                return 0;
            }
        }
        if (!snmp_cstrcat
                (buf, buf_len, out_len, allow_realloc, ""))
        {
            //(buf, buf_len, out_len, allow_realloc, "\"")) {
            return 0;
        }
        if (!sprint_realloc_asciistring
                (buf, buf_len, out_len, allow_realloc, var->val.string,
                 var->val_len))
        {
            return 0;
        }
        if (!snmp_cstrcat(buf, buf_len, out_len, allow_realloc, ""))
        {
            //if (!snmp_cstrcat(buf, buf_len, out_len, allow_realloc, "\"")) {
            return 0;
        }
    }

    if (units)
    {
        return (snmp_cstrcat(buf, buf_len, out_len, allow_realloc, " ")
                && snmp_cstrcat(buf, buf_len, out_len, allow_realloc, units));
    }
    return 1;
}

int
sprint_realloc_bitstring_my(u_char ** buf, size_t * buf_len, size_t * out_len,
                            int allow_realloc,
                            const netsnmp_variable_list * var,
                            const struct enum_list *enums,
                            const char *hint, const char *units)
{
    int             len, bit;
    u_char         *cp;
    char           *enum_string;

    if ((var->type != ASN_BIT_STR && var->type != ASN_OCTET_STR) &&
            (!netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICKE_PRINT)))
    {
        u_char          str[] = "Wrong Type (should be BITS): ";
        if (snmp_strcat(buf, buf_len, out_len, allow_realloc, str))
        {
            return sprint_realloc_by_type(buf, buf_len, out_len,
                                          allow_realloc, var, NULL, NULL,
                                          NULL);
        }
        else
        {
            return 0;
        }
    }

    if (netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICK_PRINT))
    {
        u_char          str[] = "\"";
        if (!snmp_strcat(buf, buf_len, out_len, allow_realloc, str))
        {
            return 0;
        }
    }
    else
    {
        u_char          str[] = "";
        //u_char          str[] = "BITS: ";
        if (!snmp_strcat(buf, buf_len, out_len, allow_realloc, str))
        {
            return 0;
        }
    }
    if (!sprint_realloc_hexstring(buf, buf_len, out_len, allow_realloc,
                                  var->val.bitstring, var->val_len))
    {
        return 0;
    }

    if (netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICK_PRINT))
    {
        u_char          str[] = "\"";
        if (!snmp_strcat(buf, buf_len, out_len, allow_realloc, str))
        {
            return 0;
        }
    }
    else
    {
        cp = var->val.bitstring;
        for (len = 0; len < (int) var->val_len; len++)
        {
            for (bit = 0; bit < 8; bit++)
            {
                if (*cp & (0x80 >> bit))
                {
                    enum_string = NULL;
                    for (; enums; enums = enums->next)
                    {
                        if (enums->value == (len * 8) + bit)
                        {
                            enum_string = enums->label;
                            break;
                        }
                    }
                    if (enum_string == NULL ||
                            netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID,
                                                   NETSNMP_DS_LIB_PRINT_NUMERIC_ENUM))
                    {
                        char            str[16];
                        sprintf(str, "%d ", (len * 8) + bit);
                        if (!snmp_strcat
                                (buf, buf_len, out_len, allow_realloc,
                                 (const u_char *) str))
                        {
                            return 0;
                        }
                    }
                    else
                    {
                        char            str[16];
                        sprintf(str, "(%d) ", (len * 8) + bit);
                        if (!snmp_strcat
                                (buf, buf_len, out_len, allow_realloc,
                                 (const u_char *) enum_string))
                        {
                            return 0;
                        }
                        if (!snmp_strcat
                                (buf, buf_len, out_len, allow_realloc,
                                 (const u_char *) str))
                        {
                            return 0;
                        }
                    }
                }
            }
            cp++;
        }
    }
    return 1;
}

int
sprint_realloc_counter64_my(u_char ** buf, size_t * buf_len, size_t * out_len,
                            int allow_realloc,
                            const netsnmp_variable_list * var,
                            const struct enum_list *enums,
                            const char *hint, const char *units)
{
    char            a64buf[I64CHARSZ + 1];

    if ((var->type != ASN_COUNTER64
#ifdef NETSNMP_WITH_OPAQUE_SPECIAL_TYPES
            && var->type != ASN_OPAQUE_COUNTER64
            && var->type != ASN_OPAQUE_I64 && var->type != ASN_OPAQUE_U64
#endif
        ) && (!netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICKE_PRINT)))
    {
        if (snmp_cstrcat(buf, buf_len, out_len, allow_realloc,
                         "Wrong Type (should be Counter64): "))
        {
            return sprint_realloc_by_type(buf, buf_len, out_len,
                                          allow_realloc, var, NULL, NULL,
                                          NULL);
        }
        else
        {
            return 0;
        }
    }

    if (!netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICK_PRINT))
    {
#ifdef NETSNMP_WITH_OPAQUE_SPECIAL_TYPES
        if (var->type != ASN_COUNTER64)
        {
            if (!snmp_cstrcat
                    (buf, buf_len, out_len, allow_realloc, ""))
            {
                //(buf, buf_len, out_len, allow_realloc, "Opaque: ")) {
                return 0;
            }
        }
#endif
#ifdef NETSNMP_WITH_OPAQUE_SPECIAL_TYPES
        switch (var->type)
        {
        case ASN_OPAQUE_U64:
            if (!snmp_cstrcat
                    (buf, buf_len, out_len, allow_realloc, ""))
            {
                //(buf, buf_len, out_len, allow_realloc, "UInt64: ")) {
                return 0;
            }
            break;
        case ASN_OPAQUE_I64:
            if (!snmp_cstrcat
                    (buf, buf_len, out_len, allow_realloc, ""))
            {
                //(buf, buf_len, out_len, allow_realloc, "Int64: ")) {
                return 0;
            }
            break;
        case ASN_COUNTER64:
        case ASN_OPAQUE_COUNTER64:
#endif
            if (!snmp_cstrcat
                    (buf, buf_len, out_len, allow_realloc, ""))
            {
                //(buf, buf_len, out_len, allow_realloc, "Counter64: ")) {
                return 0;
            }
#ifdef NETSNMP_WITH_OPAQUE_SPECIAL_TYPES
        }
#endif
    }
#ifdef NETSNMP_WITH_OPAQUE_SPECIAL_TYPES
    if (var->type == ASN_OPAQUE_I64)
    {
        printI64(a64buf, var->val.counter64);
        if (!snmp_cstrcat(buf, buf_len, out_len, allow_realloc, a64buf))
        {
            return 0;
        }
    }
    else
    {
#endif
        printU64(a64buf, var->val.counter64);
        if (!snmp_cstrcat(buf, buf_len, out_len, allow_realloc, a64buf))
        {
            return 0;
        }
#ifdef NETSNMP_WITH_OPAQUE_SPECIAL_TYPES
    }
#endif

    if (units)
    {
        return (snmp_cstrcat(buf, buf_len, out_len, allow_realloc, " ")
                && snmp_cstrcat(buf, buf_len, out_len, allow_realloc, units));
    }
    return 1;
}

int
sprint_realloc_float_my(u_char ** buf, size_t * buf_len,
                        size_t * out_len, int allow_realloc,
                        const netsnmp_variable_list * var,
                        const struct enum_list *enums,
                        const char *hint, const char *units)
{
    if ((var->type != ASN_OPAQUE_FLOAT) &&
            (!netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICKE_PRINT)))
    {
        if (snmp_cstrcat(buf, buf_len, out_len, allow_realloc,
                         "Wrong Type (should be Float): "))
        {
            return sprint_realloc_by_type(buf, buf_len, out_len,
                                          allow_realloc, var, NULL, NULL,
                                          NULL);
        }
        else
        {
            return 0;
        }
    }

    if (!netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICK_PRINT))
    {
        if (!snmp_cstrcat
                (buf, buf_len, out_len, allow_realloc, ""))
        {
            //(buf, buf_len, out_len, allow_realloc, "Opaque: Float: ")) {
            return 0;
        }
    }


    /*
     * How much space needed for max. length float?  128 is overkill.
     */

    while ((*out_len + 128 + 1) >= *buf_len)
    {
        if (!(allow_realloc && snmp_realloc(buf, buf_len)))
        {
            return 0;
        }
    }

    sprintf((char *) (*buf + *out_len), "%f", *var->val.floatVal);
    *out_len += strlen((char *) (*buf + *out_len));

    if (units)
    {
        return (snmp_cstrcat(buf, buf_len, out_len, allow_realloc, " ")
                && snmp_cstrcat(buf, buf_len, out_len, allow_realloc, units));
    }
    return 1;
}

int
sprint_realloc_double_my(u_char ** buf, size_t * buf_len,
                         size_t * out_len, int allow_realloc,
                         const netsnmp_variable_list * var,
                         const struct enum_list *enums,
                         const char *hint, const char *units)
{
    if ((var->type != ASN_OPAQUE_DOUBLE) &&
            (!netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICKE_PRINT)))
    {
        if (snmp_cstrcat
                (buf, buf_len, out_len, allow_realloc,
                 "Wrong Type (should be Double): "))
        {
            return sprint_realloc_by_type(buf, buf_len, out_len,
                                          allow_realloc, var, NULL, NULL,
                                          NULL);
        }
        else
        {
            return 0;
        }
    }

    if (!netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICK_PRINT))
    {
        if (!snmp_cstrcat
                (buf, buf_len, out_len, allow_realloc, ""))
        {
            //(buf, buf_len, out_len, allow_realloc, "Opaque: Float: ")) {
            return 0;
        }
    }

    /*
     * How much space needed for max. length double?  128 is overkill.
     */

    while ((*out_len + 128 + 1) >= *buf_len)
    {
        if (!(allow_realloc && snmp_realloc(buf, buf_len)))
        {
            return 0;
        }
    }

    sprintf((char *) (*buf + *out_len), "%f", *var->val.doubleVal);
    *out_len += strlen((char *) (*buf + *out_len));

    if (units)
    {
        return (snmp_cstrcat
                (buf, buf_len, out_len, allow_realloc, " ")
                && snmp_cstrcat(buf, buf_len, out_len, allow_realloc, units));
    }
    return 1;
}

int
sprint_realloc_opaque_my(u_char ** buf, size_t * buf_len,
                         size_t * out_len, int allow_realloc,
                         const netsnmp_variable_list * var,
                         const struct enum_list *enums,
                         const char *hint, const char *units)
{
    if ((var->type != ASN_OPAQUE
#ifdef NETSNMP_WITH_OPAQUE_SPECIAL_TYPES
            && var->type != ASN_OPAQUE_COUNTER64
            && var->type != ASN_OPAQUE_U64
            && var->type != ASN_OPAQUE_I64
            && var->type != ASN_OPAQUE_FLOAT && var->type != ASN_OPAQUE_DOUBLE
#endif                          /* NETSNMP_WITH_OPAQUE_SPECIAL_TYPES */
        ) && (!netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICKE_PRINT)))
    {
        if (snmp_cstrcat(buf, buf_len, out_len, allow_realloc,
                         "Wrong Type (should be Opaque): "))
        {
            return sprint_realloc_by_type(buf, buf_len, out_len,
                                          allow_realloc, var, NULL, NULL,
                                          NULL);
        }
        else
        {
            return 0;
        }
    }
#ifdef NETSNMP_WITH_OPAQUE_SPECIAL_TYPES
    switch (var->type)
    {
    case ASN_OPAQUE_COUNTER64:
    case ASN_OPAQUE_U64:
    case ASN_OPAQUE_I64:
        return sprint_realloc_counter64_my(buf, buf_len, out_len,
                                           allow_realloc, var, enums, hint,
                                           units);
        break;

    case ASN_OPAQUE_FLOAT:
        return sprint_realloc_float_my(buf, buf_len, out_len, allow_realloc,
                                       var, enums, hint, units);
        break;

    case ASN_OPAQUE_DOUBLE:
        return sprint_realloc_double_my(buf, buf_len, out_len, allow_realloc,
                                        var, enums, hint, units);
        break;

    case ASN_OPAQUE:
#endif
        if (!netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICK_PRINT))
        {
            u_char          str[] = "";
            //u_char          str[] = "OPAQUE: ";
            if (!snmp_strcat(buf, buf_len, out_len, allow_realloc, str))
            {
                return 0;
            }
        }
        if (!sprint_realloc_hexstring(buf, buf_len, out_len, allow_realloc,
                                      var->val.string, var->val_len))
        {
            return 0;
        }
#ifdef NETSNMP_WITH_OPAQUE_SPECIAL_TYPES
    }
#endif
    if (units)
    {
        return (snmp_strcat
                (buf, buf_len, out_len, allow_realloc,
                 (const u_char *) " ")
                && snmp_strcat(buf, buf_len, out_len, allow_realloc,
                               (const u_char *) units));
    }
    return 1;
}


/**
 * Prints an object identifier into a buffer.
 *
 * If allow_realloc is true the buffer will be (re)allocated to fit in the
 * needed size. (Note: *buf may change due to this.)
 *
 * @param buf      Address of the buffer to print to.
 * @param buf_len  Address to an integer containing the size of buf.
 * @param out_len  Incremented by the number of characters printed.
 * @param allow_realloc if not zero reallocate the buffer to fit the
 *                      needed size.
 * @param var      The variable to encode.
 * @param enums    The enumeration ff this variable is enumerated. may be NULL.
 * @param hint     Contents of the DISPLAY-HINT clause of the MIB.
 *                 See RFC 1903 Section 3.1 for details. may be NULL.
 * @param units    Contents of the UNITS clause of the MIB. may be NULL.
 *
 * @return 1 on success, or 0 on failure (out of memory, or buffer to
 *         small when not allowed to realloc.)
 */
int
sprint_realloc_object_identifier_my(u_char ** buf, size_t * buf_len,
                                    size_t * out_len, int allow_realloc,
                                    const netsnmp_variable_list * var,
                                    const struct enum_list *enums,
                                    const char *hint, const char *units)
{
    int             buf_overflow = 0;

    if ((var->type != ASN_OBJECT_ID) &&
            (!netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICKE_PRINT)))
    {
        u_char          str[] =
            "Wrong Type (should be OBJECT IDENTIFIER): ";
        if (snmp_strcat(buf, buf_len, out_len, allow_realloc, str))
        {
            return sprint_realloc_by_type(buf, buf_len, out_len,
                                          allow_realloc, var, NULL, NULL,
                                          NULL);
        }
        else
        {
            return 0;
        }
    }

    if (!netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICK_PRINT))
    {
        u_char          str[] = "";
        //u_char          str[] = "OID: ";
        if (!snmp_strcat(buf, buf_len, out_len, allow_realloc, str))
        {
            return 0;
        }
    }

    netsnmp_sprint_realloc_objid_tree(buf, buf_len, out_len, allow_realloc,
                                      &buf_overflow,
                                      (oid *) (var->val.objid),
                                      var->val_len / sizeof(oid));

    if (buf_overflow)
    {
        return 0;
    }

    if (units)
    {
        return (snmp_strcat
                (buf, buf_len, out_len, allow_realloc,
                 (const u_char *) " ")
                && snmp_strcat(buf, buf_len, out_len, allow_realloc,
                               (const u_char *) units));
    }
    return 1;
}

/**
 * @internal
 * Converts timeticks to hours, minutes, seconds string.
 *
 * @param timeticks    The timeticks to convert.
 * @param buf          Buffer to write to, has to be at
 *                     least 40 Bytes large.
 *
 * @return The buffer.
 */
static char    *
uptimeString(u_long timeticks, char *buf, size_t buflen)
{
    int             centisecs, seconds, minutes, hours, days;

    if (netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_NUMERIC_TIMETICKS))
    {
        snprintf(buf, buflen, "%lu", timeticks);
        return buf;
    }


    centisecs = timeticks % 100;
    timeticks /= 100;
    days = timeticks / (60 * 60 * 24);
    timeticks %= (60 * 60 * 24);

    hours = timeticks / (60 * 60);
    timeticks %= (60 * 60);

    minutes = timeticks / 60;
    seconds = timeticks % 60;

    if (netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICK_PRINT))
        snprintf(buf, buflen, "%d:%d:%02d:%02d.%02d",
                 days, hours, minutes, seconds, centisecs);
    else
    {
        if (days == 0)
        {
            snprintf(buf, buflen, "%d:%02d:%02d.%02d",
                     hours, minutes, seconds, centisecs);
        }
        else if (days == 1)
        {
            snprintf(buf, buflen, "%d day, %d:%02d:%02d.%02d",
                     days, hours, minutes, seconds, centisecs);
        }
        else
        {
            snprintf(buf, buflen, "%d days, %d:%02d:%02d.%02d",
                     days, hours, minutes, seconds, centisecs);
        }
    }
    return buf;
}

int
sprint_realloc_timeticks_my(u_char ** buf, size_t * buf_len, size_t * out_len,
                            int allow_realloc,
                            const netsnmp_variable_list * var,
                            const struct enum_list *enums,
                            const char *hint, const char *units)
{
    char            timebuf[40];

    if ((var->type != ASN_TIMETICKS) &&
            (!netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICKE_PRINT)))
    {
        u_char          str[] = "Wrong Type (should be Timeticks): ";
        if (snmp_strcat(buf, buf_len, out_len, allow_realloc, str))
        {
            return sprint_realloc_by_type(buf, buf_len, out_len,
                                          allow_realloc, var, NULL, NULL,
                                          NULL);
        }
        else
        {
            return 0;
        }
    }

    if (netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_NUMERIC_TIMETICKS))
    {
        char            str[16];
        sprintf(str, "%lu", *(u_long *) var->val.integer);
        if (!snmp_strcat
                (buf, buf_len, out_len, allow_realloc, (const u_char *) str))
        {
            return 0;
        }
        return 1;
    }
    if (!netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICK_PRINT))
    {
        char            str[32];
        sprintf(str, "(%lu) ", *(u_long *) var->val.integer);
        //sprintf(str, "Timeticks: (%lu) ", *(u_long *) var->val.integer);
        if (!snmp_strcat
                (buf, buf_len, out_len, allow_realloc, (const u_char *) str))
        {
            return 0;
        }
    }
    uptimeString(*(u_long *) (var->val.integer), timebuf, sizeof(timebuf));
    if (!snmp_strcat
            (buf, buf_len, out_len, allow_realloc, (const u_char *) timebuf))
    {
        return 0;
    }
    if (units)
    {
        return (snmp_strcat
                (buf, buf_len, out_len, allow_realloc,
                 (const u_char *) " ")
                && snmp_strcat(buf, buf_len, out_len, allow_realloc,
                               (const u_char *) units));
    }
    return 1;
}

int
sprint_realloc_gauge_my(u_char ** buf, size_t * buf_len, size_t * out_len,
                        int allow_realloc,
                        const netsnmp_variable_list * var,
                        const struct enum_list *enums,
                        const char *hint, const char *units)
{
    char            tmp[32];

    if ((var->type != ASN_GAUGE) &&
            (!netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICKE_PRINT)))
    {
        u_char          str[] =
            "Wrong Type (should be Gauge32 or Unsigned32): ";
        if (snmp_strcat(buf, buf_len, out_len, allow_realloc, str))
        {
            return sprint_realloc_by_type(buf, buf_len, out_len,
                                          allow_realloc, var, NULL, NULL,
                                          NULL);
        }
        else
        {
            return 0;
        }
    }

    if (!netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICK_PRINT))
    {
        u_char          str[] = "";
        //u_char          str[] = "Gauge32: ";
        if (!snmp_strcat(buf, buf_len, out_len, allow_realloc, str))
        {
            return 0;
        }
    }
    if (hint)
    {
        if (!sprint_realloc_hinted_integer(buf, buf_len, out_len,
                                           allow_realloc,
                                           *var->val.integer, 'u', hint,
                                           units))
        {
            return 0;
        }
    }
    else
    {
        sprintf(tmp, "%lu", *var->val.integer);
        if (!snmp_strcat
                (buf, buf_len, out_len, allow_realloc, (const u_char *) tmp))
        {
            return 0;
        }
    }
    if (units)
    {
        return (snmp_strcat
                (buf, buf_len, out_len, allow_realloc,
                 (const u_char *) " ")
                && snmp_strcat(buf, buf_len, out_len, allow_realloc,
                               (const u_char *) units));
    }
    return 1;
}

int
sprint_realloc_counter_my(u_char ** buf, size_t * buf_len, size_t * out_len,
                          int allow_realloc,
                          const netsnmp_variable_list * var,
                          const struct enum_list *enums,
                          const char *hint, const char *units)
{
    char            tmp[32];

    if ((var->type != ASN_COUNTER) &&
            (!netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICKE_PRINT)))
    {
        u_char          str[] = "Wrong Type (should be Counter32): ";
        if (snmp_strcat(buf, buf_len, out_len, allow_realloc, str))
        {
            return sprint_realloc_by_type(buf, buf_len, out_len,
                                          allow_realloc, var, NULL, NULL,
                                          NULL);
        }
        else
        {
            return 0;
        }
    }

    if (!netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICK_PRINT))
    {
        u_char          str[] = "";
        //u_char          str[] = "Counter32: ";
        if (!snmp_strcat(buf, buf_len, out_len, allow_realloc, str))
        {
            return 0;
        }
    }
    sprintf(tmp, "%lu", *var->val.integer);
    if (!snmp_strcat
            (buf, buf_len, out_len, allow_realloc, (const u_char *) tmp))
    {
        return 0;
    }
    if (units)
    {
        return (snmp_strcat
                (buf, buf_len, out_len, allow_realloc,
                 (const u_char *) " ")
                && snmp_strcat(buf, buf_len, out_len, allow_realloc,
                               (const u_char *) units));
    }
    return 1;
}

int
sprint_realloc_ipaddress_my(u_char ** buf, size_t * buf_len, size_t * out_len,
                            int allow_realloc,
                            const netsnmp_variable_list * var,
                            const struct enum_list *enums,
                            const char *hint, const char *units)
{
    u_char         *ip = var->val.string;

    if ((var->type != ASN_IPADDRESS) &&
            (!netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICKE_PRINT)))
    {
        u_char          str[] = "Wrong Type (should be IpAddress): ";
        if (snmp_strcat(buf, buf_len, out_len, allow_realloc, str))
        {
            return sprint_realloc_by_type(buf, buf_len, out_len,
                                          allow_realloc, var, NULL, NULL,
                                          NULL);
        }
        else
        {
            return 0;
        }
    }

    if (!netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICK_PRINT))
    {
        /*u_char          str[] = "IpAddress: ";*/
        u_char          str[] = "";
        if (!snmp_strcat(buf, buf_len, out_len, allow_realloc, str))
        {
            return 0;
        }
    }
    while ((*out_len + 17) >= *buf_len)
    {
        if (!(allow_realloc && snmp_realloc(buf, buf_len)))
        {
            return 0;
        }
    }
    if (ip)
        sprintf((char *) (*buf + *out_len), "%d.%d.%d.%d",
                ip[0], ip[1], ip[2], ip[3]);
    *out_len += strlen((char *) (*buf + *out_len));
    return 1;
}

int
sprint_realloc_null_my(u_char ** buf, size_t * buf_len, size_t * out_len,
                       int allow_realloc,
                       const netsnmp_variable_list * var,
                       const struct enum_list *enums,
                       const char *hint, const char *units)
{
    if ((var->type != ASN_NULL) &&
            (!netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICKE_PRINT)))
    {
        u_char          str[] = "Wrong Type (should be NULL): ";
        if (snmp_strcat(buf, buf_len, out_len, allow_realloc, str))
        {
            return sprint_realloc_by_type(buf, buf_len, out_len,
                                          allow_realloc, var, NULL, NULL,
                                          NULL);
        }
        else
        {
            return 0;
        }
    }
    else
    {
        u_char          str[] = "";
        //u_char          str[] = "NULL";
        return snmp_strcat(buf, buf_len, out_len, allow_realloc, str);
    }
}

int
sprint_realloc_uinteger_my(u_char ** buf, size_t * buf_len, size_t * out_len,
                           int allow_realloc,
                           const netsnmp_variable_list * var,
                           const struct enum_list *enums,
                           const char *hint, const char *units)
{
    char           *enum_string = NULL;

    if ((var->type != ASN_UINTEGER) &&
            (!netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICKE_PRINT)))
    {
        u_char          str[] = "Wrong Type (should be UInteger32): ";
        if (snmp_strcat(buf, buf_len, out_len, allow_realloc, str))
        {
            return sprint_realloc_by_type(buf, buf_len, out_len,
                                          allow_realloc, var, NULL, NULL,
                                          NULL);
        }
        else
        {
            return 0;
        }
    }

    for (; enums; enums = enums->next)
    {
        if (enums->value == *var->val.integer)
        {
            enum_string = enums->label;
            break;
        }
    }

    if (enum_string == NULL ||
            netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_PRINT_NUMERIC_ENUM))
    {
        if (hint)
        {
            if (!(sprint_realloc_hinted_integer(buf, buf_len, out_len,
                                                allow_realloc,
                                                *var->val.integer, 'u',
                                                hint, units)))
            {
                return 0;
            }
        }
        else
        {
            char            str[16];
            sprintf(str, "%lu", *var->val.integer);
            if (!snmp_strcat
                    (buf, buf_len, out_len, allow_realloc,
                     (const u_char *) str))
            {
                return 0;
            }
        }
    }
    else if (netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICK_PRINT))
    {
        if (!snmp_strcat
                (buf, buf_len, out_len, allow_realloc,
                 (const u_char *) enum_string))
        {
            return 0;
        }
    }
    else
    {
        char            str[16];
        sprintf(str, "(%lu)", *var->val.integer);
        if (!snmp_strcat
                (buf, buf_len, out_len, allow_realloc,
                 (const u_char *) enum_string))
        {
            return 0;
        }
        if (!snmp_strcat
                (buf, buf_len, out_len, allow_realloc, (const u_char *) str))
        {
            return 0;
        }
    }

    if (units)
    {
        return (snmp_strcat
                (buf, buf_len, out_len, allow_realloc,
                 (const u_char *) " ")
                && snmp_strcat(buf, buf_len, out_len, allow_realloc,
                               (const u_char *) units));
    }
    return 1;
}

/**
 * Universal print routine, prints a variable into a buffer according to the variable
 * type.
 *
 * If allow_realloc is true the buffer will be (re)allocated to fit in the
 * needed size. (Note: *buf may change due to this.)
 *
 * @param buf      Address of the buffer to print to.
 * @param buf_len  Address to an integer containing the size of buf.
 * @param out_len  Incremented by the number of characters printed.
 * @param allow_realloc if not zero reallocate the buffer to fit the
 *                      needed size.
 * @param var      The variable to encode.
 * @param enums    The enumeration ff this variable is enumerated. may be NULL.
 * @param hint     Contents of the DISPLAY-HINT clause of the MIB.
 *                 See RFC 1903 Section 3.1 for details. may be NULL.
 * @param units    Contents of the UNITS clause of the MIB. may be NULL.
 *
 * @return 1 on success, or 0 on failure (out of memory, or buffer to
 *         small when not allowed to realloc.)
 */
int
sprint_realloc_by_type_my(u_char ** buf, size_t * buf_len, size_t * out_len,
                          int allow_realloc,
                          const netsnmp_variable_list * var,
                          const struct enum_list *enums,
                          const char *hint, const char *units)
{
    DEBUGMSGTL(("output", "sprint_by_type, type %d\n", var->type));

    switch (var->type)
    {
    case ASN_INTEGER:
        return sprint_realloc_integer_my(buf, buf_len, out_len, allow_realloc,
                                         var, enums, hint, units);
    case ASN_OCTET_STR:
        return sprint_realloc_octet_string_my(buf, buf_len, out_len,
                                              allow_realloc, var, enums, hint,
                                              units);
    case ASN_BIT_STR:
        return sprint_realloc_bitstring_my(buf, buf_len, out_len,
                                           allow_realloc, var, enums, hint,
                                           units);
    case ASN_OPAQUE:
        return sprint_realloc_opaque_my(buf, buf_len, out_len, allow_realloc,
                                        var, enums, hint, units);
    case ASN_OBJECT_ID:
        return sprint_realloc_object_identifier_my(buf, buf_len, out_len,
                allow_realloc, var, enums,
                hint, units);
    case ASN_TIMETICKS:
        return sprint_realloc_timeticks_my(buf, buf_len, out_len,
                                           allow_realloc, var, enums, hint,
                                           units);
    case ASN_GAUGE:
        return sprint_realloc_gauge_my(buf, buf_len, out_len, allow_realloc,
                                       var, enums, hint, units);
    case ASN_COUNTER:
        return sprint_realloc_counter_my(buf, buf_len, out_len, allow_realloc,
                                         var, enums, hint, units);
    case ASN_IPADDRESS:
        return sprint_realloc_ipaddress_my(buf, buf_len, out_len,
                                           allow_realloc, var, enums, hint,
                                           units);
    case ASN_NULL:
        return sprint_realloc_null_my(buf, buf_len, out_len, allow_realloc,
                                      var, enums, hint, units);
    case ASN_UINTEGER:
        return sprint_realloc_uinteger_my(buf, buf_len, out_len,
                                          allow_realloc, var, enums, hint,
                                          units);
    case ASN_COUNTER64:
#ifdef NETSNMP_WITH_OPAQUE_SPECIAL_TYPES
    case ASN_OPAQUE_U64:
    case ASN_OPAQUE_I64:
    case ASN_OPAQUE_COUNTER64:
#endif                          /* NETSNMP_WITH_OPAQUE_SPECIAL_TYPES */
        return sprint_realloc_counter64_my(buf, buf_len, out_len,
                                           allow_realloc, var, enums, hint,
                                           units);
#ifdef NETSNMP_WITH_OPAQUE_SPECIAL_TYPES
    case ASN_OPAQUE_FLOAT:
        return sprint_realloc_float_my(buf, buf_len, out_len, allow_realloc,
                                       var, enums, hint, units);
    case ASN_OPAQUE_DOUBLE:
        return sprint_realloc_double_my(buf, buf_len, out_len, allow_realloc,
                                        var, enums, hint, units);
#endif                          /* NETSNMP_WITH_OPAQUE_SPECIAL_TYPES */
    default:
        DEBUGMSGTL(("sprint_by_type", "bad type: %d\n", var->type));
        return sprint_realloc_badtype_my(buf, buf_len, out_len, allow_realloc,
                                         var, enums, hint, units);
    }
}

int
sprint_realloc_variable_my(u_char ** buf, size_t * buf_len,
                           size_t * out_len, int allow_realloc,
                           const oid * objid, size_t objidlen,
                           const netsnmp_variable_list * variable,
                           int flag_return)
{
	if(flag_return)
	{
	    int buf_overflow = 0;

	        netsnmp_sprint_realloc_objid_tree(buf, buf_len, out_len,
	                                          allow_realloc, &buf_overflow,
	                                          objid, objidlen);


	    if (buf_overflow) {
	        return 0;
	    }
	    if (!netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_PRINT_BARE_VALUE)) {
	        if (netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICKE_PRINT)) {
	            if (!snmp_strcat
	                (buf, buf_len, out_len, allow_realloc,
	                 (const u_char *) " = ")) {
	                return 0;
	            }
	        } else {
	            if (netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICK_PRINT)) {
	                if (!snmp_strcat
	                    (buf, buf_len, out_len, allow_realloc,
	                     (const u_char *) " ")) {
	                    return 0;
	                }
	            } else {
	                if (!snmp_strcat
	                    (buf, buf_len, out_len, allow_realloc,
	                     (const u_char *) " = ")) {
	                    return 0;
	                }
	            }                   // end if-else NETSNMP_DS_LIB_QUICK_PRINT
	        }                       // end if-else NETSNMP_DS_LIB_QUICKE_PRINT
	    } else {
	        *out_len = 0;
	    }
	}
/*

    if (variable->type == SNMP_NOSUCHOBJECT)
    {
        return snmp_strcat(buf, buf_len, out_len, allow_realloc,
                           (const u_char *)
                           "No Such Object available on this agent at this OID");
    }
    else if (variable->type == SNMP_NOSUCHINSTANCE)
    {
        return snmp_strcat(buf, buf_len, out_len, allow_realloc,
                           (const u_char *)
                           "No Such Instance currently exists at this OID");
    }
    else if (variable->type == SNMP_ENDOFMIBVIEW)
    {
        return snmp_strcat(buf, buf_len, out_len, allow_realloc,
                           (const u_char *)
                           "No more variables left in this MIB View (It is past the end of the MIB tree)");
    }
    else    */
    {
        /*
         * Handle rare case where tree is empty.
         */
        return sprint_realloc_by_type_my(buf, buf_len, out_len, allow_realloc,
                                         variable, 0, 0, 0);
    }
}

/**
 * Prints a variable to a file descriptor.
 *
 * @param f         The file descriptor to print to.
 * @param objid     The object id.
 * @param objidlen  The length of teh object id.
 * @param variable  The variable to print.
 */
/*void
fprint_variable_my(const oid * objid,
                size_t objidlen, const netsnmp_variable_list * variable)*/
void
fprint_variable_my(const oid * objid,
                   size_t objidlen, const netsnmp_variable_list * variable, snmp_arg *argv, snmp_walk_callback cb, int flag_return)

{
    u_char         *buf = NULL;
    size_t          buf_len = 256, out_len = 0;

    if ((buf = (u_char *) calloc(buf_len, 1)) == NULL)
    {
        return;
    }
    else
    {
        if (sprint_realloc_variable_my(&buf, &buf_len, &out_len, 1,
                                       objid, objidlen, variable, flag_return))
        {
            if(NULL != cb)
                cb(argv, (char *)buf);
        }
        else
        {
        }
    }

    SNMP_FREE(buf);
}

void
fprint_variable_myget(const oid * objid,
                      size_t objidlen, const netsnmp_variable_list * variable, char *out_para, int flag_return)

{
    u_char         *buf = NULL;
    size_t          buf_len = 256, out_len = 0;

    if ((buf = (u_char *) calloc(buf_len, 1)) == NULL)
    {
        return;
    }
    else
    {
        if (sprint_realloc_variable_my(&buf, &buf_len, &out_len, 1,
                                       objid, objidlen, variable, flag_return))
        {
			if(NULL != out_para)
                strncpy(out_para, (char *)buf, 256);
        }
        else
        {
        }
    }

    SNMP_FREE(buf);
}

/*mibs*/

void
snmp_get_and_print(netsnmp_session * ss, oid * theoid, size_t theoid_len)
{
    netsnmp_pdu    *pdu, *response;
    netsnmp_variable_list *vars;
    int             status;

    pdu = snmp_pdu_create(SNMP_MSG_GET);
    snmp_add_null_var(pdu, theoid, theoid_len);

    status = snmp_synch_response(ss, pdu, &response);
    if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR)
    {
        for (vars = response->variables; vars; vars = vars->next_variable)
        {
            numprinted++;
            print_variable(vars->name, vars->name_length, vars);
        }
    }
    if (response)
    {
        snmp_free_pdu(response);
    }
}

int
snmp_walk(snmp_arg *argv,   snmp_walk_callback cb, int flag_return)
{
    netsnmp_session session, *ss;
    netsnmp_pdu    *pdu, *response;
    netsnmp_variable_list *vars;
    oid             name[MAX_OID_LEN];
    size_t          name_length;
    oid             root[MAX_OID_LEN];
    size_t          rootlen;
    int             count;
    int             running;
    int             status;
    int             check;
    int             exitval = 0;
    struct timeval  tv1, tv2;
    char tmp_peername[64] = {0};
	long tmp_snmp_version = my_config_info.snmp_version;
	numprinted = 0;

    sprintf(tmp_peername, "%s:%d", argv->peer_name, my_config_info.scan_port);

    netsnmp_ds_register_config(ASN_BOOLEAN, "snmpwalk", "dontCheckOrdering",
			       NETSNMP_DS_APPLICATION_ID,
			       NETSNMP_DS_WALK_DONT_CHECK_LEXICOGRAPHIC);
version1_retry:

    snmp_sess_init(&session);
	/*
	 * -C c :do not check returned OIDs are increasing
	 */
	if(flag_return)
	    netsnmp_ds_toggle_boolean(NETSNMP_DS_APPLICATION_ID,
		    NETSNMP_DS_WALK_DONT_CHECK_LEXICOGRAPHIC);
    /*
     * read in MIB database and initialize the snmp library
    */
    init_snmp("snmpapp");
    /*
     * set the arguments
     */
    session.version= tmp_snmp_version;
    session.peername = strdup(tmp_peername);
    session.community = (u_char *)strdup(argv->community);
    session.community_len = strlen((char *)session.community);
    session.retries = my_config_info.retries;
    session.timeout = my_config_info.snmptimeout * 1000000L;

    /*
     * get the initial object and subtree
     */
    rootlen = MAX_OID_LEN;
    if (snmp_parse_oid(argv->oid, root, &rootlen) == NULL)
    {
        snmp_perror(argv->oid);
        if(session.peername){
            free(session.peername);
            session.peername = NULL;
        }
        if(session.community){
            free(session.community);
            session.community = NULL;
        }
        return -1;
    }

    SOCK_STARTUP;

    /*
     * open an SNMP session
     */
    ss = snmp_open(&session);
    if (ss == NULL)
    {
        /*
         * diagnose snmp_open errors with the input netsnmp_session pointer
         */
        if(session.peername){
            free(session.peername);
            session.peername = NULL;
        }
        if(session.community){
            free(session.community);
            session.community = NULL;
        }
        snmp_sess_perror("mysnmpwalk", &session);
        SOCK_CLEANUP;
        return -1;
    }

    /*
     * get first object to start walk
     */
    memmove(name, root, rootlen * sizeof(oid));
    name_length = rootlen;

    running = 1;

    check =
        !netsnmp_ds_get_boolean(NETSNMP_DS_APPLICATION_ID,
                                NETSNMP_DS_WALK_DONT_CHECK_LEXICOGRAPHIC);
    if (netsnmp_ds_get_boolean(NETSNMP_DS_APPLICATION_ID, NETSNMP_DS_WALK_INCLUDE_REQUESTED))
    {
        snmp_get_and_print(ss, root, rootlen);
    }

    if (netsnmp_ds_get_boolean(NETSNMP_DS_APPLICATION_ID,
                               NETSNMP_DS_WALK_TIME_RESULTS))
        gettimeofday(&tv1, NULL);
    while (running)
    {
        /*
         * create PDU for GETNEXT request and add object name to request
         */
        pdu = snmp_pdu_create(SNMP_MSG_GETNEXT);
        snmp_add_null_var(pdu, name, name_length);

        /*
         * do the request
         */
        status = snmp_synch_response(ss, pdu, &response);
        if (status == STAT_SUCCESS)
        {
            if (response->errstat == SNMP_ERR_NOERROR)
            {
                /*
                 * check resulting variables
                 */
                for (vars = response->variables; vars;
                        vars = vars->next_variable)
                {
                    if ((vars->name_length < rootlen)
                            || (memcmp(root, vars->name, rootlen * sizeof(oid))
                                != 0))
                    {
                        /*
                         * not part of this subtree
                         */
                        running = 0;
                        continue;
                    }
                    numprinted++;
                    fprint_variable_my(vars->name, vars->name_length, vars, argv, cb, flag_return);
                    if ((vars->type != SNMP_ENDOFMIBVIEW) &&
                            (vars->type != SNMP_NOSUCHOBJECT) &&
                            (vars->type != SNMP_NOSUCHINSTANCE))
                    {
                        /*
                         * not an exception value
                         */
                        if (0 && check
                                && snmp_oid_compare(name, name_length,
                                                    vars->name,
                                                    vars->name_length) >= 0)
                        {
                            _DEBUG_FILE("-----MYSNMP-----Error: OID not increasing: %s %d >= %s %d\n",
                                        name, name_length, vars->name, vars->name_length);
                            /*fprint_objid(stderr, name, name_length);
                            fprintf(stderr, " >= ");
                            fprint_objid(stderr, vars->name,
                                         vars->name_length);
                            fprintf(stderr, "\n");*/
                            running = 0;
                            exitval = 1;
                        }
                        memmove((char *) name, (char *) vars->name,
                                vars->name_length * sizeof(oid));
                        name_length = vars->name_length;
                    }
                    else
                        /*
                         * an exception value, so stop
                         */
                        running = 0;
                }
            }
            else
            {
                /*
                 * error in response, print it
                 */
                running = 0;
                if (response->errstat == SNMP_ERR_NOSUCHNAME)
                {
                    _DEBUG_FILE("-----MYSNMP-----End of MIB\n");
                }
                else
                {
                    _DEBUG_FILE("-----MYSNMP-----Error in packet.\nReason: %s\n",
                                snmp_errstring(response->errstat));
                    if (response->errindex != 0)
                    {
                        _DEBUG_FILE("-----MYSNMP-----Failed object: ");
                        for (count = 1, vars = response->variables;
                                vars && count != response->errindex;
                                vars = vars->next_variable, count++)
                            /*EMPTY*/;
                        if (vars)
                            _DEBUG_FILE("%s %d\n", vars->name, vars->name_length);
                    }
                    exitval = 2;
                }
            }
        }
        else if (status == STAT_TIMEOUT)
        {
            _DEBUG_FILE("-----MYSNMP-----Timeout: No Response from %s\n", session.peername);
            running = 0;
            exitval = 4;
        }
        else                    /* status == STAT_ERROR */
        {
            snmp_sess_perror("mysnmp", ss);
            running = 0;
            exitval = 1;
        }
        if (response)
            snmp_free_pdu(response);
    }
    if (netsnmp_ds_get_boolean(NETSNMP_DS_APPLICATION_ID,
                               NETSNMP_DS_WALK_TIME_RESULTS))
        gettimeofday(&tv2, NULL);

    if (numprinted == 0 && status == STAT_SUCCESS)
    {
        /*
         * no printed successful results, which may mean we were
         * pointed at an only existing instance.  Attempt a GET, just
         * for get measure.
         */
        if (!netsnmp_ds_get_boolean(NETSNMP_DS_APPLICATION_ID, NETSNMP_DS_WALK_DONT_GET_REQUESTED))
        {
            snmp_get_and_print(ss, root, rootlen);
			exitval = 3;
        }
    }

    /*free the strdup.*/
    if(session.peername){
        free(session.peername);
        session.peername = NULL;
    }
    if(session.community){
        free(session.community);
        session.community = NULL;
    }
    snmp_close(ss);

    if (netsnmp_ds_get_boolean(NETSNMP_DS_APPLICATION_ID,
                               NETSNMP_DS_WALK_PRINT_STATISTICS))
    {
        _DEBUG_FILE("-----MYSNMP-----Variables found: %d\n", numprinted);
    }
    if (netsnmp_ds_get_boolean(NETSNMP_DS_APPLICATION_ID,
                               NETSNMP_DS_WALK_TIME_RESULTS))
    {
        _DEBUG_FILE("-----MYSNMP-----Total traversal time = %f seconds\n",
                    (double) (tv2.tv_usec - tv1.tv_usec)/1000000 +
                    (double) (tv2.tv_sec - tv1.tv_sec));
    }

    SOCK_CLEANUP;

	if(exitval==4 && tmp_snmp_version==SNMP_VERSION_2c)
	{
		tmp_snmp_version = SNMP_VERSION_1;
		exitval = 0;
		_DEBUG_FILE("[%s] %s using snmp version 1 to try again.\n", __func__, argv->peer_name);
		goto version1_retry;
	}

    return exitval;
}

int
snmp_get(snmp_arg *argv,   char *out_para, int flag_return)
{
    netsnmp_session session, *ss;
    netsnmp_pdu    *pdu;
    netsnmp_pdu    *response;
    netsnmp_variable_list *vars;
    int             count;
    int             current_name = 1;
    oid             name[MAX_OID_LEN];
    size_t          name_length;
    int             status;
    int             failures = 0;
    int             exitval = 0;
    char tmp_peername[64] = {0};
	long tmp_snmp_version = my_config_info.snmp_version;

    sprintf(tmp_peername, "%s:%d", argv->peer_name, my_config_info.scan_port);
version1_retry:
    snmp_sess_init(&session);
    /*
     * read in MIB database and initialize the snmp library
    */
    init_snmp("snmpapp");

    /*
     * set the arguments
     */
    session.version = tmp_snmp_version;
    session.peername = strdup(tmp_peername);
    session.community = (u_char *)strdup(argv->community);
    session.community_len = strlen((char *)session.community);
    session.retries = my_config_info.retries;
    session.timeout = my_config_info.snmptimeout * 1000000L;

    SOCK_STARTUP;

    /*
     * Open an SNMP session.
     */
    ss = snmp_open(&session);
    if (ss == NULL)
    {
        /*
         * diagnose snmp_open errors with the input netsnmp_session pointer
         */
        snmp_sess_perror("mysnmpget", &session);
        SOCK_CLEANUP;
        if(session.peername){
            free(session.peername);
            session.peername = NULL;
        }
        if(session.community){
            free(session.community);
            session.community = NULL;
        }
        return -1;
    }


    /*
     * Create PDU for GET request and add object names to request.
     */
    pdu = snmp_pdu_create(SNMP_MSG_GET);
    for (count = 0; count < current_name; count++)
    {
        name_length = MAX_OID_LEN;
        if (!snmp_parse_oid(argv->oid, name, &name_length))
        {
            snmp_perror(argv->oid);
            failures++;
        }
        else
            snmp_add_null_var(pdu, name, name_length);
    }
    if (failures)
    {
        snmp_close(ss);
        SOCK_CLEANUP;
        if(session.peername){
            free(session.peername);
            session.peername = NULL;
        }
        if(session.community){
            free(session.community);
            session.community = NULL;
        }
        return -1;
    }


    /*
     * Perform the request.
     *
     * If the Get Request fails, note the OID that caused the error,
     * "fix" the PDU (removing the error-prone OID) and retry.
     */
retry:
    status = snmp_synch_response(ss, pdu, &response);
    if (status == STAT_SUCCESS)
    {
        if (response->errstat == SNMP_ERR_NOERROR)
        {
            for (vars = response->variables; vars;
                    vars = vars->next_variable)
            {
                if (vars->type == SNMP_NOSUCHOBJECT
                        || vars->type == SNMP_NOSUCHINSTANCE
                        || vars->type == SNMP_ENDOFMIBVIEW)
                {
                        exitval = 3;
						break;
                }
                    fprint_variable_myget(vars->name, vars->name_length, vars, out_para, flag_return);
            }
        }
        else
        {
            _DEBUG_FILE("-----MYSNMP-----Error in packet\nReason: %s\n",
                        snmp_errstring(response->errstat));

            if (response->errindex != 0)
            {
                _DEBUG_FILE("-----MYSNMP-----Failed object: ");
                for (count = 1, vars = response->variables;
                        vars && count != response->errindex;
                        vars = vars->next_variable, count++)
                    /*EMPTY*/;
                if (vars)
                {
                    _DEBUG_FILE("%s %d", vars->name, vars->name_length);
                }
                _DEBUG_FILE("\n");
            }
            exitval = 2;

            /*
             * retry if the errored variable was successfully removed
             */
            if (!netsnmp_ds_get_boolean(NETSNMP_DS_APPLICATION_ID,
                                        NETSNMP_DS_APP_DONT_FIX_PDUS))
            {
                pdu = snmp_fix_pdu(response, SNMP_MSG_GET);
                snmp_free_pdu(response);
                response = NULL;
                if (pdu != NULL)
                {
                    goto retry;
                }
            }
        }                       /* endif -- SNMP_ERR_NOERROR */

    }
    else if (status == STAT_TIMEOUT)
    {
        _DEBUG_FILE("-----MYSNMP-----Timeout: No Response from %s.\n",
                    session.peername);
        exitval = 4;

    }
    else                        /* status == STAT_ERROR */
    {
        snmp_sess_perror("mysnmpget", ss);
        exitval = 1;

    }                           /* endif -- STAT_SUCCESS */

    /*free the strdup.*/
    if(session.peername){
        free(session.peername);
        session.peername = NULL;
    }
    if(session.community){
        free(session.community);
        session.community = NULL;
    }

    if (response)
        snmp_free_pdu(response);
    snmp_close(ss);
    SOCK_CLEANUP;

	if(exitval==4 && tmp_snmp_version==SNMP_VERSION_2c)
	{
		tmp_snmp_version = SNMP_VERSION_1;
		exitval = 0;
		_DEBUG_FILE("[%s] %s using snmp version 1 to try again.\n", __func__, argv->peer_name);
		goto version1_retry;
	}

	argv->version = tmp_snmp_version;

    return exitval;

}

