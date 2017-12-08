#include "capturethread.h"
#include "sniffer.h"
#include <ctime>
#include <stdio.h>
#include <stdlib.h>
#include"log.h"

namespace Ui {
    class MainWindow;
}
CaptureThread::CaptureThread()
{

}

CaptureThread::CaptureThread(Sniffer *psniffer, QString tmpfilename, MultiView *view, Filter *f)
{
    bstop = false;
    sniffer = psniffer;
    filename = tmpfilename;
    this->view = view;
    this->filter = f;
}

void CaptureThread::setCondition()
{
    bstop=true;
}

void CaptureThread::stop()
{
    bstop = true;
}

bool CaptureThread::getCondition()
{
    return bstop;
}

void CaptureThread::run()
{   //open net device && capture packet && save

    int res;//save the result of catth packet

    QByteArray      rawByteData;
    int             num=1;
    bool fileFlag; // whether the packet my contain file data
    char            sizeNum[10];
    char            sizeLength[6];
    time_t          local_tv_sec;
    struct          tm* ltime;   //tm defined in time.h
    char            timestr[16];

    //int             whetherFragment=0;

    //open net device

    if(!sniffer->openNetDevInSniffer()) {
        LOG("error:there is no device abailable");
        //exit(1);
    }

    LOG("open net device successfully");

    //open the file to save info of packets
    if(!filename.isEmpty()) {
        if(sniffer->openDumpFile((const char*)filename.toLocal8Bit())) {
            LOG("open file successfully");
        }
        else {
            LOG("Failed to open file");
        }
    }

    pslideInfo=new SlideInfo;

    while (bstop!=true &&(res=sniffer->captureOnce())>=0) {
        //msleep(1);
        SnifferData tmpSnifferData;
        fileFlag = false;
        tmpSnifferData.protoInfo.strSendInfo = QByteArray("");
        // out of time,wait for packet
        if(res==0) {
            LOG("wait for packet");
            continue;
        }
        //

        LOG("start capture");

        sniffer->saveCaptureData();   //write raw info to the file named filename

        rawByteData.clear();
        rawByteData.setRawData((const char*)sniffer->pktData,sniffer->header->caplen);  //save packet to qbytearray

        tmpSnifferData.strData="raw capture data:" ;//+rawByteData.toHex().toUpper();
        tmpSnifferData.strData.append(rawByteData.toHex().toUpper());

        local_tv_sec=sniffer->header->ts.tv_sec;  //seconds since 1900
        ltime=localtime(&local_tv_sec); //get local time
        strftime(timestr,sizeof(timestr),"%H:%M:%S", ltime);

        tmpSnifferData.strTime=timestr;

        sprintf(sizeLength,"%d",sniffer->header->len);
        tmpSnifferData.strLength=sizeLength;

        /*above:just write the packet to file,without analyze
         *
         * then:begin to analyze packet
         */

        _eth_header   *eth; //ethernet
        _ip_header    *iph;
        _arp_header   *arph;
        _tcp_header   *tcph;
        _udp_header   *udph;
        _icmp_header  *icmph;
        _igmp_header  *igmph;

        int flag;
        flag=0;

        unsigned short sport=0,dport=0;
        unsigned char* sip;
        unsigned char* dip;
        unsigned int ip_lenth;
        //QString  rebuildInfo;
        //rebuildInfo="";

        //First get Mac header

        eth=new _eth_header();
        memcpy(eth, sniffer->pktData, sizeof(_eth_header));
        tmpSnifferData.protoInfo.peth = (void*) eth;

        //Second get ip header

/********************************************IP begin****************************************/
       if(htons(eth->eth_type)==2048) {     //there is somthing wrong about this sentence

            LOG("it is IP packet");

            flag=1;
            iph=new _ip_header();
            memcpy(iph, sniffer->pktData+14, sizeof(_ip_header));

            tmpSnifferData.protoInfo.ipFlag = EPT_IP;
            tmpSnifferData.protoInfo.pip = (void*) iph;

            //get length of ip header
            ip_lenth=(iph->ver_ihl &0xF)*4;  //get lenth of ip title
            sip = iph->saddr;
            dip = iph->daddr;

            //above:finished processing ip header
/**************************************ip slide and rebuild*************************************/

            if(!pslideInfo->checkWhetherSlide(iph,tmpSnifferData,rawByteData)) {
                LOG("in if");
                //pass,don't fragment
            } else {
                LOG("get a slide of ip packet!!!!!!!!!!!!!!!!!");

                if(pslideInfo->complete) {
                    LOG("rebuild a full packet");
                    iph->flags_fo=0x0000;//pass
                    tmpSnifferData.strProto+="(Rebuild)";
                    QByteArray tmpHeaderByteData;
                    tmpHeaderByteData.clear();

                    tmpHeaderByteData.setRawData((const char*)sniffer->pktData,14+ip_lenth);
                    //tmpSnifferData.strData.clear();
                    tmpSnifferData.strData="raw capture data:";
                    //LOG(tmpSnifferData.strData.size());
                    tmpSnifferData.strData.append(tmpHeaderByteData.toHex().toUpper());
                    //LOG(tmpSnifferData.strData.size());
                    tmpSnifferData.strData.append(pslideInfo->rebuildByteData);


                    unsigned int rebuildLength;
                    char            rebuildSizeLength[6];
                    rebuildLength=ip_lenth+pslideInfo->rebuildTotalLength+14;
                    sprintf(rebuildSizeLength,"%d",rebuildLength);
                    tmpSnifferData.strLength=rebuildSizeLength;
                } else {
                    continue; //can't form an intact ip packet
                }
            }

/**************************************higher protocol on ip************************************/
            switch(iph->proto) {
            case TCP_SIG:
                tcph=new _tcp_header();
                if(!pslideInfo->complete) {
                    memcpy(tcph, sniffer->pktData+14+ip_lenth, sizeof(_tcp_header));
                } else {
                    memcpy(tcph, pslideInfo->rebuildByteData.data(), sizeof(_tcp_header));
                }
                //memcpy(tcph, sniffer->pktData+14+ip_lenth, sizeof(_tcp_header));
                tmpSnifferData.protoInfo.tcpFlag = TCP_SIG;
                tmpSnifferData.protoInfo.ptcp = (void*) tcph;
                tmpSnifferData.protoInfo.ipProto = QObject::tr("TCP");
                tmpSnifferData.strProto += "TCP";

                sport=ntohs(tcph->sport);
                dport=ntohs(tcph->dport);


/**************************************tcp high protocol begin**********************************/
                if(sport==FTP_PORT||dport==FTP_PORT) {
                    tmpSnifferData.strProto+="(FTP)";
                    tmpSnifferData.protoInfo.appFlag = FTP_PORT;
                } else if (sport ==SMTP_PORT||dport==SMTP_PORT) {
                    tmpSnifferData.strProto+="(SMTP)";
                    tmpSnifferData.protoInfo.appFlag = SMTP_PORT;
                } else if (sport ==TELNET_PORT||dport==TELNET_PORT) {
                    tmpSnifferData.strProto+="(TELNET)";
                    tmpSnifferData.protoInfo.appFlag = TELNET_PORT;
                } else if(sport==POP3_PORT||dport==POP3_PORT) {
                    tmpSnifferData.strProto+="(POP3)";
                    tmpSnifferData.protoInfo.appFlag = POP3_PORT;
                } else if (sport == HTTPS_PORT || dport == HTTPS_PORT) {
                    tmpSnifferData.strProto += "(HTTPS)";
                    tmpSnifferData.protoInfo.appFlag+= HTTPS_PORT;
                } else if (sport == HTTP_PORT || dport == HTTP_PORT ||
                         sport == HTTP2_PORT || dport == HTTP2_PORT) {
                    tmpSnifferData.strProto += "(HTTP)";
                    tmpSnifferData.protoInfo.appFlag = HTTP_PORT;
                } else {
                    tmpSnifferData.protoInfo.appFlag = 0;
                    fileFlag = true;
                }
                tmpSnifferData.protoInfo.strSendInfo = rawByteData.remove(0, 54);
                break;

            case UDP_SIG:
                tmpSnifferData.strProto="UDP";
                tmpSnifferData.strProtoForShow="User Datagram Protocol";

                udph=new _udp_header();
                if(!pslideInfo->complete) {
                    memcpy(udph, sniffer->pktData+14+ip_lenth, sizeof(_udp_header));
                } else {
                    memcpy(udph, pslideInfo->preheader, sizeof(_udp_header));
                }
                //memcpy(udph, sniffer->pktData+14+ip_lenth, sizeof(_udp_header));
                tmpSnifferData.protoInfo.tcpFlag = UDP_SIG;
                tmpSnifferData.protoInfo.ptcp = (void*) udph;
                tmpSnifferData.protoInfo.ipProto = QObject::tr("UDP");

                sport=ntohs(udph->sport);
                dport=ntohs(udph->dport);

                if (sport == DNS_PORT || dport == DNS_PORT) {
                    tmpSnifferData.strProto += "(DNS)";
                    tmpSnifferData.protoInfo.appFlag = DNS_PORT;
                } else if (sport == SNMP_PORT || dport == SNMP_PORT) {
                    tmpSnifferData.strProto += "(SNMP)";
                    tmpSnifferData.protoInfo.appFlag = SNMP_PORT;
                } else {
                    tmpSnifferData.protoInfo.appFlag = 0;
                }
                break;

            case ICMP_SIG:
                tmpSnifferData.strProto+="ICMP";

                icmph=new _icmp_header();
                if(!pslideInfo->complete) {
                    memcpy(icmph, sniffer->pktData+14+ip_lenth, sizeof(_icmp_header));
                } else {
                    LOG("hhh");
                    memcpy(icmph,(pslideInfo->rebuildheader.data()), sizeof(_icmp_header));
                    LOG((icmph->type));
                }
                //memcpy(icmph, sniffer->pktData+14+ip_lenth, sizeof(_icmp_header));
                tmpSnifferData.protoInfo.tcpFlag = ICMP_SIG;
                tmpSnifferData.protoInfo.ptcp = (void*) icmph;
                tmpSnifferData.protoInfo.ipProto = QObject::tr("ICMP");
                break;
            case IGMP_SIG:
                tmpSnifferData.strProto="IGMP";

                igmph=new _igmp_header();
                if(!pslideInfo->complete) {
                    memcpy(igmph, sniffer->pktData+14+ip_lenth, sizeof(_igmp_header));
                } else {
                    memcpy(igmph, pslideInfo->preheader, sizeof(_igmp_header));
                }
                memcpy(igmph, sniffer->pktData+14+ip_lenth, sizeof(_igmp_header));
                tmpSnifferData.protoInfo.tcpFlag = IGMP_SIG;
                tmpSnifferData.protoInfo.ptcp = (void*) igmph;
                tmpSnifferData.protoInfo.ipProto = QObject::tr("IGMP");
                break;
            default:
                LOG("Nothing captured!!!");
                continue;
            }

       }else if(htons(eth->eth_type)==2054) {


            LOG("it is arp packet")

            flag=1;

            tmpSnifferData.strProto="ARP";
            //get arp protocol header
            arph = new _arp_header();
            memcpy(arph, (sniffer->pktData+14), sizeof(_arp_header));
            tmpSnifferData.protoInfo.ipFlag = EPT_ARP;
            tmpSnifferData.protoInfo.pip = (void*) arph;

            sip = arph->arp_spa;
            dip = arph->arp_tpa;


        } else {
            LOG("unknown proto");
        }
        char strsip[24], strdip[24];
        sprintf(strsip,"%d.%d.%d.%d",sip[0],sip[1],sip[2],sip[3]);
        sprintf(strdip,"%d.%d.%d.%d",dip[0],dip[1],dip[2],dip[3]);
        tmpSnifferData.strSIP=strsip;
        tmpSnifferData.strSIP=tmpSnifferData.strSIP+":"+QString::number(sport,10);
        tmpSnifferData.strDIP=strdip;
        tmpSnifferData.strDIP=tmpSnifferData.strDIP+":"+QString::number(dport,10);

        if (fileFlag && tmpSnifferData.protoInfo.strSendInfo.size()>100) {
            view->addFilePacket(tmpSnifferData.strSIP+tmpSnifferData.strDIP, ntohl(tcph->seq_no), num-1);
        }


        if (flag==1&&bstop==false) {

            sprintf(sizeNum,"%d",num);
            tmpSnifferData.strNum=sizeNum;   //strNum is the sequence number of the packet
            view->addPacketItem(tmpSnifferData, true, filter->launchOneFilter(tmpSnifferData));
            num++;

        }

    }
    delete pslideInfo;
}
