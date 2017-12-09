#include "slideinfo.h"
#include "type.h"
#include <netdb.h>
#include <functional>
#include <algorithm>
#include <iostream>
#include "log.h"

bool LessSort(slideSort a,slideSort b){return a.sortOffset<b.sortOffset;}

bool operator ==(SlidePacketInfo &a,const SlidePacketInfo &b) {
    if(a.fragmentIdentification==b.fragmentIdentification && a.fragmentOffset==b.fragmentOffset) {
        return true;
    } else {
        return false;
    }
}

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
    //LOG("plug in insert");
    std::vector<SlidePacketInfo>::const_iterator its;
    its=find(packetInfoForRebuild.begin(),packetInfoForRebuild.end(),tmpslide);
    if(its==packetInfoForRebuild.end()) {   //it is a new packet
        packetInfoForRebuild.push_back(tmpslide);
        if(tmpslide.fragmentFlag==false && tmpslide.fragmentOffset!=0) {LOG("get tail");}
        if(tmpslide.fragmentFlag==true && tmpslide.fragmentOffset==0) {LOG("get head");}
    }  //discard repetitive packets
    //packetInfoForRebuild.push_back(tmpslide);
    return true;
}

bool SlideInfo::checkWhetherSlide(_ip_header* iph,SnifferData &tmpsnifferdata,QByteArray & rawbyte) {
    SlidePacketInfo tmpSlidePacketInfo;
    rebuildTotalLength=0;
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
    tmpSlidePacketInfo.fragmentheader.clear();
    //tmpSlidePacketInfo.fragmentByteData.setRawData((const char*)(iph+(iph->ver_ihl & 0x0F)*4),(ntohs(iph->tlen)-(iph->ver_ihl & 0x0F)*4));
    //tmpSlidePacketInfo.fragmentByteData.resize((ntohs(iph->tlen)-(iph->ver_ihl & 0x0F)*4));
    tmpSlidePacketInfo.fragmentByteData=tmpsnifferdata.strData.mid(14+(iph->ver_ihl & 0x0F)*4,(ntohs(iph->tlen)-(iph->ver_ihl & 0x0F)*4));
    tmpSlidePacketInfo.header=(void*)(iph+(iph->ver_ihl & 0x0F)*4);
    tmpSlidePacketInfo.fragmentheader=rawbyte.mid(14+(iph->ver_ihl & 0x0F)*4,(ntohs(iph->tlen)-(iph->ver_ihl & 0x0F)*4));

    //tmpSlidePacketInfo.fragmenthead.setRawData((const char*)(resniffer.pktData+14+(iph->ver_ihl & 0x0F)*4),)
    //tmpSlidePacketInfo.fragmentByteData.resize((ntohs(iph->tlen)-(iph->ver_ihl & 0x0F)*4));
    /*for(int i=0;i<(ntohs(iph->tlen)-(iph->ver_ihl & 0x0F)*4);i++) {
        tmpSlidePacketInfo.fragmentByteData.append(tmpsnifferdata.strData[51+i]);
    }*/


    QString testbytedata=tmpSlidePacketInfo.fragmentheader.toHex().toUpper();
    QString testbyte1=QObject::tr("");
    testbyte1.append(testbytedata[0]);
    testbyte1.append(testbytedata[1]);
    testbyte1.append(testbytedata[2]);
    testbyte1.append(testbytedata[3]);
    LOG(testbyte1.toStdString());


    tmpSlidePacketInfo.nextFragmentOffset=(ntohs(iph->tlen)-(iph->ver_ihl & 0x0F)*4)/8+tmpSlidePacketInfo.fragmentOffset; //the unit of offset is 8 bytes


    LOG("OFFSET");
    LOG(tmpSlidePacketInfo.fragmentOffset);
    LOG(tmpSlidePacketInfo.fragmentByteData.size());

    QString test=testbytedata;
    //test=tmpSlidePacketInfo.fragmentByteData;

    LOG("plug in 1");
    if(!(tmpSlidePacketInfo.fragmentFlag==1||tmpSlidePacketInfo.fragmentOffset!=0)) {
        return false;
    } else {
        insertPacket(tmpSlidePacketInfo);
        //LOG("back to check");
        rebuildInfo();
        //LOG("back to check after rebuild");
        return true;
    }

}

bool SlideInfo::rebuildInfo() {
    for(std::vector<int>::iterator it=allIpId.begin();it!=allIpId.end();it++) {
        sequence.clear();
        rebuildByteData.clear();
        headFlag=false;
        tailFlag=false;
        complete=false;
        //LOG("plug in rebuild");
        for(std::vector<SlidePacketInfo>::iterator its=packetInfoForRebuild.begin();its!=packetInfoForRebuild.end();its++) {
            if(*it==its->fragmentIdentification) {
                if(its->fragmentFlag==false && its->fragmentOffset!=0) {tailFlag=true;}
                if(its->fragmentFlag==true && its->fragmentOffset==0) {headFlag=true;}
                slideSort tmpSlideSort;
                tmpSlideSort.index=its-packetInfoForRebuild.begin();
                tmpSlideSort.sortOffset=its->fragmentOffset;
                sequence.push_back(tmpSlideSort);
                //LOG("loop2 end");
            }
        }// loop2 end

        LOG("REBUILD 1");

        std::sort(sequence.begin(),sequence.end(),LessSort);
        for(std::vector<slideSort>::iterator it2=sequence.begin();(it2+1)!=(sequence.end())&&it2!=sequence.end();++it2) {
            LOG("while");

            LOG(it2->index);

            if(tailFlag&&headFlag) {
               if(packetInfoForRebuild.at(it2->index).nextFragmentOffset==packetInfoForRebuild.at((it2+1)->index).fragmentOffset) {
                    LOG(packetInfoForRebuild.size());
                    //LOG("TRUE");
                    complete=true;
               } else {
                   //LOG("FALSE");
                   complete=false;
                   break;
               }
            } else{
                complete=false;
                break;
            }


        }//loop3 end,fine okay

        LOG("rebuild 2");
        if(complete) {
            rebuildByteData.clear();
            preheader=NULL;
            rebuildTotalLength=packetInfoForRebuild.at((sequence.end()-1)->index).nextFragmentOffset*8;
            LOG(rebuildTotalLength);
            for(std::vector<slideSort>::iterator it2=(sequence.begin());it2!=(sequence.end());++it2) {
                LOG("yes");
                LOG(packetInfoForRebuild.at(it2->index).fragmentByteData.size());
                if(it2==sequence.begin()) {
                    LOG("header");
                    preheader=packetInfoForRebuild.at(it2->index).header;
                    rebuildheader=packetInfoForRebuild.at(it2->index).fragmentheader;
                }
                rebuildByteData.append(packetInfoForRebuild.at(it2->index).fragmentByteData);

                LOG(rebuildByteData.size());
                //packetInfoForRebuild.erase(packetInfoForRebuild.begin()+it2->index);
            } //delete all packets info which is already rebuilt
            for(int si=packetInfoForRebuild.size()-1;si>=0;si--) {

                if(packetInfoForRebuild[si].fragmentIdentification==*it) {
                    packetInfoForRebuild.erase(packetInfoForRebuild.begin()+si);
                }
                //std::vector<SlidePacketInfo> itpacket;
                //std::find(packetInfoForRebuild.begin(),packetInfoForRebuild.end(),)
            } //delete all packets info which is already rebuilt
            allIpId.erase(it);
            if(isFull()) {
                packetInfoForRebuild.clear();
            }

            LOG("TOTAL LENGTH");

            QString test;
            test=rebuildByteData.toHex().toUpper();
            for(int i=0;i<8;i++) {
                std::cout<<test[i].toLatin1()<<std::endl;
            }

            return true;
        }
    } //loop1 end

    if(isFull()) {
        packetInfoForRebuild.clear();
    }
    return false;

}
