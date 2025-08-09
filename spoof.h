#pragma once

#include <pcap.h>
#include "ip.h"
#include "mac.h"

struct IpMac {
    Ip  ip;
    Mac mac;
};

bool arp_spoof(const char* interface, const char* senderIp, const char* targetIp);