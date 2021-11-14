all:l2send

CFLAGS=-g
l2send: l2send.o
        gcc -g $^ -o $@ -lpcap


run:
        sudo ./l2send enp0s8.301 1s

clean:
        -rm *.o l2send
