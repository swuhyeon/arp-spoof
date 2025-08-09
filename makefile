LDLIBS=-lpcap

all: arp-spoof

main.o: mac.h spoof.h ip.h ethhdr.h arphdr.h main.cpp

spoof.o: spoof.cpp spoof.h ethhdr.h arphdr.h ip.h mac.h

arphdr.o: mac.h ip.h arphdr.h arphdr.cpp

ethhdr.o: mac.h ethhdr.h ethhdr.cpp

ip.o: ip.h ip.cpp

mac.o : mac.h mac.cpp

arp-spoof: main.o spoof.o arphdr.o ethhdr.o ip.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f arp-spoof *.o
