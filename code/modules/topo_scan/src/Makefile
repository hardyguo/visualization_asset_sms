BINDIR = /usr/local/sbin/
TARGET = "topo_scan"
CC = gcc
FLAGS = `pkg-config --cflags glib-2.0` -Wall -g
SRCS = main.c handle_hash.c thread_pool.c common.c icmp_snmp.c handle_mysql.c handle_snmp.c switch_link.c queue.c
INCLUDES = -I../include -I/usr/include/mysql/ -I/usr/include/ -I/usr/lib/glib-2.0/include -I/usr/include/glib-2.0 -I../../nmap-7.12
LIB_PATH = -L/usr/lib/ -L/usr/lib/x86_64-linux-gnu/ -L/usr/local/lib/
LIBS = -lmysqlclient -lnetsnmp -lscan -lglib-2.0  -lgthread-2.0 -lpthread `pkg-config --libs glib-2.0`
all:
	$(CC) $(FLAGS) -o $(TARGET) $(SRCS) $(INCLUDES) $(LIB_PATH) $(LIBS)

install:
	cp $(TARGET) $(BINDIR)

clean:
	-rm -rf *.o $(TARGET)

