#ifndef CSNIFFER_H
#define CSNIFFER_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pcap.h>
#include <netdb.h>
#define PCAP_OPENFLAG_PROMISCUOUS 1
#define PCAP_BUF_SIZE 2048

#include <iostream>
using namespace std;

class Csniffer {
protected:
    struct pcap_pkthdr *header;
    const u_char *pktData;
    pcap_if_t *pNetDevs;
    pcap_t *pHandle;
    pcap_dumper_t *pDumpFile;

    bool findAllNetDevs();
    bool capture();

public:
    Csniffer();
    ~Csniffer();
    bool openDumpFile(const char* fileName);
    bool saveCaptureData();
    bool closeDumpFile();
    bool freeNetDevs();
    bool closeNetDevs();
    bool openNetDev(char *devName, int flag=PCAP_OPENFLAG_PROMISCUOUS, int lengthLimit = 65536);
    bool setCaptureConfig(const char* config);
    char err[PCAP_BUF_SIZE];

/*
    void test() {
        findAllNetDevs();
        std::cout<<pNetDevs->name<<endl;
        openNetDev(pNetDevs->name);
        std::cout<<err<<endl;
        openDumpFile("a.txt");
        capture();
        closeNetDevs();
    }*/
};


#endif // CSNIFFER_H
