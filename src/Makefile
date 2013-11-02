# Makefile - build rules for cron/linux/user
#
# DESCRIPTION
# This file contains rules to build cron for linux(user space)
#

#include ../../../common.mak


CFLAGS = ${INCDIR} -D_X86_
#CFLAGS += -I../h 

LDFLAGS += ${LDDIR} -lpthread
#LDFLAGS += -lglueos -lsqlite3 -lccmi -lrt -lsqlextlib

BINARY =  athdev

all:
	${CC} -O2 ${CFLAGS} -o ${BINARY} athdev.c send_arp.c utils.c ${LDFLAGS}
#	cp ${BINARY} ${BINDIR}
#	cp ${BINARY} /tftpboot/

clean: 
	rm -f ${BINARY}

