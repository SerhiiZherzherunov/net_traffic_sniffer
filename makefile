TARGET = net_traffic_snf
PREFIX = /usr/local/bin

.PHONY: all clean install uninstall

all: $(TARGET)

clean:
	    rm -rf $(TARGET) *.o
main.o: main.c
	    gcc -c -o main.o main.c
help.o: help.c
	    gcc -c -o help.o help.c
daemon.o: daemon.c
	    gcc -c -o daemon.o daemon.c
sniffer.o: sniffer.c
	    gcc -c -o sniffer.o sniffer.c
parse_cmds.o: parse_cmds.c
	    gcc -c -o parse_cmds.o parse_cmds.c
traffic.o: traffic.c
	    gcc -c -o traffic.o traffic.c
$(TARGET): main.o daemon.o help.o sniffer.o parse_cmds.o traffic.o
	    gcc -o $(TARGET) main.o daemon.o help.o sniffer.o parse_cmds.o traffic.o
install:
	    install $(TARGET) $(PREFIX)
uninstall:
	    rm -rf $(PREFIX)/$(TARGET)