#ifndef SNIFFER_H
#define SNIFFER_H

#include <vector>
#include <netdb.h>
#include "csniffer.h"
#include "type.h"

class Sniffer: public Csniffer {
public:
    QString currentNetName;
    Sniffer():Csniffer(){}
    ~Sniffer(){}

    bool getNetDevInfo();
    void testPrint();
    bool captureOnce();
    std::vector<NetDevInfo> netDevInfo;   //provide available network interface info
    std::vector<SnifferData> snifferData;  //provide detail info of packets
    char* ip2s(struct sockaddr *sockaddr, int addlen, bool ipv6flag=true, char* stripv6=NULL);
};

#endif // SNIFFER_H
