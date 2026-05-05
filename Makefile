CC      = x86_64-w64-mingw32-gcc
CFLAGS  = -Wall -O2

.PHONY: all bof exe clean

all: bof

bof: edgedump.x64.o

exe: edgedump.exe

edgedump.x64.o: edgedump.c beacon.h
	$(CC) -c -DBOF $(CFLAGS) edgedump.c -o edgedump.x64.o

edgedump.exe: edgedump.c
	$(CC) $(CFLAGS) edgedump.c -o edgedump.exe -lkernel32

clean:
	rm -f edgedump.x64.o edgedump.exe
