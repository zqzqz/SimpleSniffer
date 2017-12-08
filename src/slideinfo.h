#ifndef SLIDEINFO_H
#define SLIDEINFO_H

#include <QThread>
#include <vector>
#include "type.h"




class SlideInfo
{
public:
    SlideInfo(int a=10);
    bool checkWhetherSlide(_ip_header*,SnifferData &,QByteArray &);
    bool complete;            // is get all packets to rebuild info
    QByteArray rebuildByteData;
    QByteArray rebuildheader;
    int rebuildTotalLength;
    void* preheader;

private:
    bool insertPacket(SlidePacketInfo & tmpslide);
    std::vector<SlidePacketInfo> packetInfoForRebuild;
    int defaultWindowSize;
    std::vector<int> allIpId; //save all packets' identifications which need to be rebuilt
    std::vector<slideSort> sequence;//save the sequence of the same id
    bool headFlag;
    bool tailFlag;            //flags of the first fragment and the last fragment


    bool isFull();
    bool rebuildInfo();
};
#endif // SLIDEINFO_H
