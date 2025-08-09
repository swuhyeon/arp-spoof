#include <iostream>
#include <cstdlib>
#include <cstdio>
#include "spoof.h"

using namespace std;

static void usage() {
    printf("syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
    printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

int main(int argc, char* argv[]) {
    if (argc < 4 || (argc % 2) != 0) {
        usage();
        return EXIT_FAILURE;
    }

    const char* interface = argv[1];

    for (int i = 2; i < argc; i += 2) {

        printf("interface: %s\n", interface);
        printf("pair: %s <-> %s\n", argv[i], argv[i+1]);

        if (!arp_spoof(interface, argv[i], argv[i+1])) {
            printf("couldn't arp_spoof(%s <-> %s)\n", argv[i], argv[i+1]);
        }
    }
    return EXIT_SUCCESS;
}