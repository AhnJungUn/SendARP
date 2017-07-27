#Makefile
all: send_arp

send_arp: send_arp.c
	gcc -o send_arp send_arp.c -lpcap

clean:
	rm -f send_arp

