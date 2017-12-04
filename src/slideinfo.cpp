#include "slideinfo.h"
#include "type.h"
#include <netdb.h>
#include <functional>
#include <algorithm>
#include <iostream>

bool LessSort(slideSort a,slideSort b){return a.sortOffset<b.sortOffset;}

SlideInfo::SlideInfo(int windowsize) {
    defaultWindowSize=windowsize;
}

bool SlideInfo::isFull() {
    return (packetInfoForRebuild.size()>defaultWindowSize);
}

bool SlideInfo::insertPacket(SlidePacketInfo & tmpslide) {
    if(isFull()) {
        return false;
    }
    std::vector<int>::iterator it; //find whether the identification appears before;
    it=find(allIpId.begin(),allIpId.end(),tmpslide.fragmentIdentification);
    if(it!=allIpId.end()) {
        //pass
    } else {
        allIpId.push_back(tmpslide.fragmentIdentification);
    }
    packetInfoForRebuild.push_back(tmpslide);
    return true;
}

bool SlideInfo::checkWhetherSlide(_ip_header* iph) {
    SlidePacketInfo tmpSlidePacketInfo;

    sequence.clear();
    rebuildByteData.clear();
    headFlag=false;
    tailFlag=false;
    complete=false;

    if((ntohs(iph->flags_fo) & 0x2000)/32/256){
        tmpSlidePacketInfo.fragmentFlag=true;
    } else {
        tmpSlidePacketInfo.fragmentFlag=false;
    }

    tmpSlidePacketInfo.fragmentOffset=(ntohs(iph->flags_fo) & 0x1FFF);
    tmpSlidePacketInfo.fragmentIdentification=ntohs(iph->identification);
    tmpSlidePacketInfo.fragmentByteData.clear();
    tmpSlidePacketInfo.fragmentByteData.setRawData((const char*)(iph+(iph->ver_ihl & 0x0F)*4),(ntohs(iph->tlen)-(iph->ver_ihl & 0x0F)*4));
    tmpSlidePacketInfo.nextFragmentOffset=ntohs(iph->tlen)-(iph->ver_ihl & 0x0F)*4+tmpSlidePacketInfo.fragmentOffset;
    if(!(tmpSlidePacketInfo.fragmentFlag||tmpSlidePacketInfo.fragmentOffset!=0)) {
        return false;
    } else {
        insertPacket(tmpSlidePacketInfo);
        rebuildInfo();
        return true;
    }

}

bool SlideInfo::rebuildInfo() {
    for(std::vector<int>::iterator it;it!=allIpId.begin();it++) {
        sequence.clear();
        rebuildByteData.clear();
        headFlag=false;
        tailFlag=false;
        complete=false;
        for(std::vector<SlidePacketInfo>::iterator its=packetInfoForRebuild.begin();its!=packetInfoForRebuild.end();its++) {
            if(*it==its->fragmentIdentification) {
                if(its->fragmentFlag==false && its->fragmentOffset!=0) {tailFlag=true;}
                if(its->fragmentFlag==true && its->fragmentOffset==0) {headFlag=true;}
                slideSort tmpSlideSort;
                tmpSlideSort.index=its-packetInfoForRebuild.begin();
                tmpSlideSort.sortOffset=its->fragmentOffset;
                sequence.push_back(tmpSlideSort);
            }
        }// loop2 end
        std::sort(sequence.begin(),sequence.end(),LessSort);
        for(std::vector<slideSort>::iterator it2=sequence.begin();it2!=(sequence.end()-1);++it2) {
            if(packetInfoForRebuild.at(it2->index).nextFragmentOffset==packetInfoForRebuild.at(it2->index+1).fragmentOffset) {
                complete=true;
            } else {
                complete=false;
                break;
            }
        }//loop3 end
        if(complete) {
            for(std::vector<slideSort>::iterator it2=sequence.begin();it2!=(sequence.end());++it2) {
                rebuildByteData.append(packetInfoForRebuild.at(it2->index).fragmentByteData);
                packetInfoForRebuild.erase(packetInfoForRebuild.begin()+it2->index);
            } //delete all packets info which is already rebuilt
            if(isFull()) {
                packetInfoForRebuild.clear();
            }
            return true;
        }
    } //loop1 end

    if(isFull()) {
        packetInfoForRebuild.clear();
    }
    return false;

}
