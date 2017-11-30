#include <sys/socket.h>
#include <netinet/in.h>
#include <pcap.h>
#include <iostream>
#include "csniffer.h"
#include "sniffer.h"
#include "log.h"

//Get, analysis and save network info
bool Sniffer::getNetDevInfo() {
    if (pNetDevs == NULL) {
        if (findAllNetDevs() == false) {
            LOG("no available interfaces");
            return false;
        }
    }
    pcap_addr_t *IPaddr;
    NetDevInfo takenInfo;
    char stripv6[128];
    for (pcap_if_t* i = pNetDevs; i != NULL; i = i->next) {   //for each network interface
        takenInfo.strNetDevname = i->name;
        if (i->description) {
            takenInfo.strNetDevDescribe = i->description;
        }
        else {
            takenInfo.strNetDevDescribe = "No description";
        }
        for (IPaddr = i->addresses; IPaddr != NULL; IPaddr = IPaddr->next) {   //for each address of one interface
            if (IPaddr->addr->sa_family == AF_INET) {
                takenInfo.strIPV4FamilyName="AF_INET/IPv4";
                if(IPaddr->addr) {
                    takenInfo.strIPV4Addr = ip2s(IPaddr->addr, 128, false);
                }
            }
            else if (IPaddr->addr->sa_family == AF_INET6) {
                takenInfo.strIPV6FamilyName="AF_INET/IPv6";
                if(IPaddr->addr) {
                    takenInfo.strIPV6Addr = ip2s(IPaddr->addr, 128, true, stripv6);
                }
            }
        }
        netDevInfo.push_back(takenInfo);
    }
    return true;
}

//transfer socket IP address to sring host name
char* Sniffer::ip2s(sockaddr *sockaddr, int addrlen, bool ipv6flag, char* address) {
    if (ipv6flag) {
        socklen_t sockAddrLen = sizeof(struct sockaddr_storage);
        getnameinfo(sockaddr, sockAddrLen, address, addrlen, NULL, 0, NI_NUMERICHOST);
        return address;
    }
    else {
        u_long ip = ((struct sockaddr_in *)sockaddr)->sin_addr.s_addr;
        static char output[12][3*4+3+1];
        static short which;
        u_char *p;
        p = (u_char *)&ip;
        which = (which +1 == 12 ? 0:which+1);
        sprintf(output[which], "%d.%d.%d.%d", p[0],p[1],p[2],p[3]);
        return output[which];
    }
}

//print network info to console: used for testing
void Sniffer::testPrint() {
    std::cout<<"log: "<<endl;
    for (std::vector<NetDevInfo>::iterator i = netDevInfo.begin(); i<netDevInfo.end(); i++) {
        std::cout<<i->strNetDevname<<endl<<i->strNetDevDescribe<<endl<<i->strIPV4FamilyName<<": "<<i->strIPV4Addr<<endl<<i->strIPV6FamilyName<<": "<<i->strIPV6Addr<<endl;
    }
}

int Sniffer::captureOnce() {
    return capture();
}

bool Sniffer::openNetDevInSniffer()
{
    QByteArray tmpCurrentNetName = currentNetName.toLatin1();
    char *chCurrentNetName=tmpCurrentNetName.data();
    return openNetDev(chCurrentNetName);
}
