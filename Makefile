## @file Makefile

include ../../common.mak

all:
	CC=${CC} AR=${AR} CFLAGS=${INCDIR} LDFLAGS=${LDDIR} make -C ./src

clean:
	make -C ./src clean
