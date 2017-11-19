#include <sys/socket.h>
#include <netinet/in.h>
#include <pcap.h>
#include <netdb.h>
#include "csniffer.h"
#include <iostream>
#include "log.h"


Csniffer::Csniffer() {
    pNetDevs = NULL;
    pHandle = NULL;
    pDumpFile = NULL;
}

Csniffer::~Csniffer() {
    freeNetDevs();
    closeDumpFile();
}

bool Csniffer::findAllNetDevs() {
    freeNetDevs();
    if (pcap_findalldevs(&pNetDevs, err) == -1) {
        return false;
    }
    return true;
}

bool Csniffer::openNetDev(char *devName, int flag, int lengthLimit) {
    if (pHandle != NULL) {
        closeNetDevs();
    }
    pHandle = pcap_open_live(devName, lengthLimit, flag, 1000, err);
    if (pHandle == NULL) {
        LOG("pHandle==null");
        return false;
    }
    return true;
}

bool Csniffer::closeNetDevs() {
    if (pHandle != NULL) {
        pcap_close(pHandle);
        pHandle = NULL;
        return true;
    }
    return false;
}

bool Csniffer::freeNetDevs() {
    if (pNetDevs != NULL) {
        pcap_freealldevs(pNetDevs);
        pNetDevs = NULL;
        return true;
    }
    return false;
}

bool Csniffer::setCaptureConfig(const char *config) {
    if (pcap_datalink(pHandle) != DLT_EN10MB) {
        LOG("set filter failure");
        return false;
    }
    u_int netmask = 0xffffff;  //ipv4 netmask 255.255.255.0

    struct bpf_program fcode;

    if (pcap_compile(pHandle, &fcode, config, 1, netmask) < 0 ) {   //transfer filter config string to recognized bytecode
        LOG("pcap_compile failure");
        return false;
    }
    if (pcap_setfilter(pHandle, &fcode) < 0) {     //set the filter
        LOG("pcap_setfilter failure");
        return false;
    }
    return true;
}

bool Csniffer::capture() {
    int captureResult = pcap_next_ex(pHandle, &header, &pktData);
    if (pDumpFile != NULL) {
        saveCaptureData();
    }
    return captureResult;
}

bool Csniffer::openDumpFile(const char *fileName) {
    if (pDumpFile !=NULL) {
        closeDumpFile();
    }
    if ((pDumpFile = pcap_dump_open(pHandle, fileName)) != NULL) {
        return true;
    }
    else {
        LOG(pcap_geterr(pHandle));
    }
    return false;
}

bool Csniffer::saveCaptureData() {
    if (pDumpFile != NULL) {
        pcap_dump((unsigned char *)pDumpFile, header, pktData);
        return true;
    }
    return false;
}

bool Csniffer::closeDumpFile() {
    if (pDumpFile != NULL) {
        pcap_dump_close(pDumpFile);
        pDumpFile = NULL;
        return true;
    }
    return false;
}

