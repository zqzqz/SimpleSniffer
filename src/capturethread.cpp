#include "capturethread.h"
#include "sniffer.h"
#include <ctime>
#include<stdio.h>
#include"log.h"

CaptureThread::CaptureThread(Sniffer *psniffer, QString tmpfilename)
{
    bstop = false;
    sniffer = psniffer;
    filename = tmpfilename;
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
    char            sizeNum[10];
    char            sizeLength[6];
    time_t          local_tv_sec;
    struct          tm* ltime;   //tm defined in time.h
    char            timestr[16];

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

    //clear
    sniffer->snifferData.clear();  //snifferdata is a vector

    while (bstop!=true &&(res=sniffer->captureOnce())>=0) {
        msleep(1);
        SnifferData tmpSnifferData;
        // out of time,wait for packet
        if(res==0) {
            LOG("wait for packet");
            continue;
        }
        //

        LOG("start capture");

        sniffer->saveCaptureData();   //write raw info to the file named filename

        if(sniffer->snifferData.size()>=10) {
            sniffer->snifferData.clear();
        }

        tmpSnifferData.protoInfo.init();

        rawByteData.clear();
        rawByteData.setRawData((const char*)sniffer->pktData,sniffer->header->caplen);  //save packet to qbytearray

        tmpSnifferData.strData="raw capture data:" +rawByteData.toHex().toUpper();

        sprintf(sizeNum,"%d",num);
        tmpSnifferData.strNum=sizeNum;   //strNum is the sequence number of the packet
        num++;

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

        int flag=0;

        unsigned short sport,dport;
        unsigned short arp_hard_type,arp_protocol_type;
        unsigned char  arp_hard_length,arp_protocol_length;           //maybe used later
        unsigned int ip_lenth,ip_total_lenth,arp_lenth,arp_total_lenth;
        unsigned char *pByte;
        unsigned int tcpSeqNo,tcpAckNo;

        //First get Mac header

        eth=(_eth_header*)sniffer->pktData;

        QByteArray DMac,SMac;

        DMac.setRawData((const char *)eth->dstmac,6);
        SMac.setRawData((const char *)eth->srcmac,6);
        DMac=DMac.toHex().toUpper();
        SMac=SMac.toHex().toUpper();

        tmpSnifferData.protoInfo.strDMac=tmpSnifferData.protoInfo.strDMac
                                         +DMac[0]+DMac[1]+"-"+DMac[2]+DMac[3]+"-"
                                         +DMac[4]+DMac[5]+"-"+DMac[6]+DMac[7]+"-"
                                         +DMac[8]+DMac[9]+"-"+DMac[10]+DMac[11];
        tmpSnifferData.protoInfo.strSMac=tmpSnifferData.protoInfo.strSMac
                                         +SMac[0]+SMac[1]+"-"+SMac[2]+SMac[3]+"-"
                                         +SMac[4]+SMac[5]+"-"+SMac[6]+SMac[7]+"-"
                                         +SMac[8]+SMac[9]+"-"+SMac[10]+SMac[11];

        //Second get ip header

       /***************IP begin****************************************/
       if(htons(eth->eth_type)==0x0800) {     //there is somthing wrong about this sentence

            LOG("it is IP packet");

            flag=1;

            tmpSnifferData.strProto="IP";
            tmpSnifferData.protoInfo.strType+="Internet Protocol (0x0800)";
            tmpSnifferData.protoInfo.strNetTitle+="Internet Prtocol";


            iph=(_ip_header*)(sniffer->pktData+14);//based on bytes

            //get length of ip header
            ip_lenth=(iph->ver_ihl &0xF)*4;  //get lenth of ip title

            char sizeSize[6];
            sprintf(sizeSize,"%u",ip_lenth);
            tmpSnifferData.protoInfo.strHeadLength+=sizeSize;
            tmpSnifferData.protoInfo.strHeadLength+="bytes";

            ip_total_lenth=ntohs(iph->tlen);
            sprintf(sizeSize,"%u",ip_total_lenth);
            tmpSnifferData.protoInfo.strLength+=sizeSize;
            tmpSnifferData.protoInfo.strLength+="bytes";

            char sizeSrcAddr[24],sizeDstAddr[24];  //???

            sprintf(sizeSrcAddr,"%d.%d.%d.%d",iph->saddr[0],iph->saddr[1],iph->saddr[2],iph->saddr[3]);
            sprintf(sizeDstAddr,"%d.%d.%d.%d",iph->daddr[0],iph->daddr[1],iph->daddr[2],iph->daddr[3]);

            //above:finished processing ip header

            switch(iph->proto) {
            case TCP_SIG:
                tmpSnifferData.strProto="TCP";
                tmpSnifferData.protoInfo.strNextProto+= "TCP (Transmission Control Protocol)";
                tmpSnifferData.protoInfo.strTranProto+= "TCP protocol (Transmission Control Protocol)";
                tcph=(_tcp_header *)((unsigned char *)iph+ip_lenth);
                tcpSeqNo=ntohs(tcph->seq_no);
                tcpAckNo=ntohs(tcph->ack_no);
                sport=ntohs(tcph->sport); //
                dport=ntohs(tcph->dport); //
                char sizeTcpSeqNO[12],sizeTcpAckNo[12];
                sprintf(sizeTcpSeqNO,"%u",tcpSeqNo);
                sprintf(sizeTcpAckNo,"%u",tcpAckNo);
                tmpSnifferData.protoInfo.strBasicInfo="Seq=";
                tmpSnifferData.protoInfo.strBasicInfo+=sizeTcpSeqNO;
                tmpSnifferData.protoInfo.strBasicInfo+=",Ack=";
                tmpSnifferData.protoInfo.strBasicInfo+=sizeTcpAckNo;

                if(sport==FTP_PORT||dport==FTP_PORT) {
                    tmpSnifferData.strProto="FTP";
                    tmpSnifferData.protoInfo.strAppProto+="FTP(File Transfer Protocol)";
                }/*else if(sport==TELNET_PORT||dport==TELNET_PORT){
                    tmpSnifferData.strProto+="(TELNET)";
                    tmpSnifferData.protoInfo.strAppProto+="TELNET";
                }else if(sport==TELNET_PORT||dport==TELNET_PORT) {
                    tmpSnifferData.strProto="TELNET";
                    tmpSnifferData.protoInfo.strAppProto+="TELNET";
                }*/ else if (sport ==SMTP_PORT||dport==SMTP_PORT) {
                    tmpSnifferData.strProto="SMTP";
                    tmpSnifferData.protoInfo.strAppProto+="SMTP(Simple Message Transfer Protocol)";
                } else if(sport==POP3_PORT||dport==POP3_PORT) {
                    tmpSnifferData.strProto="POP3";
                    tmpSnifferData.protoInfo.strAppProto+="POP3 (Post Office Protocol 3)";
                } else if (sport == HTTPS_PORT || dport == HTTPS_PORT) {
                    tmpSnifferData.strProto = "HTTPS";
                    tmpSnifferData.protoInfo.strAppProto += "HTTPS (Hypertext Transfer Protocol over Secure Socket Layer)";
                } else if (sport == HTTP_PORT || dport == HTTP_PORT ||
                         sport == HTTP2_PORT || dport == HTTP2_PORT) {
                    tmpSnifferData.strProto = "HTTP";
                    tmpSnifferData.protoInfo.strAppProto += "HTTP (Hyper Text Transport Protocol)";
                    tmpSnifferData.protoInfo.strSendInfo = rawByteData.remove(0, 54);
                } else {
                    tmpSnifferData.protoInfo.strAppProto += "Unknown Proto";
                }
                break;
            case UDP_SIG:
                tmpSnifferData.strProto="UDP";
                tmpSnifferData.protoInfo.strNextProto+="UDP(User Datagram Protocol)";
                tmpSnifferData.protoInfo.strTranProto+="UDP(User Datagram Protocol)";
                udph=(_udp_header*)((unsigned char *)iph+ip_lenth);
                sport=ntohs(udph->sport);
                dport=ntohs(udph->dport);
                pByte=(unsigned char *)iph+ip_lenth+sizeof(_udp_header);

                if (sport == DNS_PORT || dport == DNS_PORT) {
                    tmpSnifferData.strProto = "DNS";
                    tmpSnifferData.protoInfo.strAppProto += "DNS (Domain Name Server)";
                } else if (sport == SNMP_PORT || dport == SNMP_PORT) {
                    tmpSnifferData.strProto = "SNMP";
                    tmpSnifferData.protoInfo.strAppProto += "SNMP (Simple Network Management Protocol)";
                } else {
                    tmpSnifferData.protoInfo.strAppProto += "Unknown Proto";
                }
                break;
            case ICMP_SIG:
                tmpSnifferData.strProto="ICMP";
                tmpSnifferData.protoInfo.strNextProto+="ICMP(Internet Control Message Protocol)";
                tmpSnifferData.protoInfo.strNextProto+="ICMP(Internet Control Message Protocol)";
                icmph=(_icmp_header*)((unsigned char*)iph+ip_lenth);
                pByte=(unsigned char *)iph+ip_lenth+sizeof(_icmp_header);
                if(htons(icmph->type)==4||htons(icmph->type)==12) {
                    //tmpSnifferData.strProto="ICMP(error messages)";
                    tmpSnifferData.protoInfo.strBasicInfo="errro message";
                } else if(htons(icmph->type)==9||htons(icmph->type)==10||(htons(icmph->type)>=13 &&htons(icmph->type)<=18)) {
                    //tmpSnifferData.strProto="ICMP(operational information indicating)";
                    tmpSnifferData.protoInfo.strBasicInfo="operational information indicating";
                } else if(htons(icmph->type)==8) {
                    tmpSnifferData.protoInfo.strBasicInfo="Echo (ping) request:";

                } else if(htons(icmph->type)==0) {
                    tmpSnifferData.protoInfo.strBasicInfo="Echo (ping) reply:";

                } else if(htons(icmph->type==3)) {
                    tmpSnifferData.protoInfo.strBasicInfo="Unreachable Destination";
                } else if(htons(icmph->type)==5) {
                    tmpSnifferData.protoInfo.strBasicInfo="Redirect";
                } else if(htons(icmph->type)==11) {
                    tmpSnifferData.protoInfo.strBasicInfo="Out of time";
                } else {
                    //tmpSnifferData.protoInfo.strAppProto += "Unknown Proto";
                }
                break;
            case IGMP_SIG:
                tmpSnifferData.strProto="IGMP";
                tmpSnifferData.protoInfo.strNextProto+="IGMP(Internet Group Manager Protocol)";
                tmpSnifferData.protoInfo.strTranProto+="IGMP(Internet Group Manager Protocol)";
                igmph=(_igmp_header *)((unsigned char *)iph+ip_lenth);
                if(htons(icmph->type)==0x22) {
                    tmpSnifferData.protoInfo.strBasicInfo="Membership Report:";
                    if(igmph->numberOfSrc>0) {
                        char sizeMiltiCastAddr[24];//???
                        sprintf(sizeMiltiCastAddr,"%d.%d.%d.%d",igmph->multicastAddress[0],igmph->multicastAddress[1],igmph->multicastAddress[2],igmph->multicastAddress[3]);
                        if(htons(igmph->recordType)==4) {
                            tmpSnifferData.protoInfo.strBasicInfo+="join group";
                            tmpSnifferData.protoInfo.strBasicInfo+=sizeMiltiCastAddr;
                        } else if(htons(igmph->recordType)==3) {
                            tmpSnifferData.protoInfo.strBasicInfo+="leave group";
                            tmpSnifferData.protoInfo.strBasicInfo+=sizeMiltiCastAddr;
                        } else if(htons(igmph->recordType)==2){
                            tmpSnifferData.protoInfo.strBasicInfo+="mode is exclude";
                            tmpSnifferData.protoInfo.strBasicInfo+=sizeMiltiCastAddr;
                        } else if(htons(igmph->recordType)==1){
                            tmpSnifferData.protoInfo.strBasicInfo+="mode is include";
                            tmpSnifferData.protoInfo.strBasicInfo+=sizeMiltiCastAddr;
                        } else {
                            //pass
                        }
                    }
                } else if(htons(icmph->type)==0x11) {
                    tmpSnifferData.protoInfo.strBasicInfo="Membership Query:";
                } else {
                    //pass
                }

            default:
                LOG("Nothing captured!!!");
                continue;
            }

            char sizeSrcPort[6],sizeDstPort[6];
            sprintf(sizeSrcPort,"%d",sport);
            sprintf(sizeDstPort,"%d",dport);

            tmpSnifferData.strSIP=sizeSrcAddr;
            tmpSnifferData.strSIP=tmpSnifferData.strSIP+":"+sizeSrcPort;
            tmpSnifferData.strDIP=sizeDstAddr;
            tmpSnifferData.strDIP=tmpSnifferData.strDIP+":"+sizeDstPort;

            tmpSnifferData.protoInfo.strSIP+=sizeSrcAddr;
            tmpSnifferData.protoInfo.strDIP+=sizeDstAddr;
            tmpSnifferData.protoInfo.strSPort+=sizeSrcPort;
            tmpSnifferData.protoInfo.strDPort+=sizeDstPort;

        }
       /***************IP end****************************************/

       /***************ARP begin*************************************/

        else if(htons(eth->eth_type)==0x0806) {

            LOG("it is arp packet")

            flag=1;

            tmpSnifferData.protoInfo.strType+="Address Resolution Protocol (0x0806)";
            tmpSnifferData.protoInfo.strNetTitle+="Address Resolution Protocol";
            tmpSnifferData.strProto="ARP";
            //get arp protocol header
            arph=(_arp_header *)(sniffer->pktData+14);

            arp_lenth=8;
            arp_total_lenth=42;
            char arpSizeSize[6];
            sprintf(arpSizeSize,"%u",arp_lenth);
            tmpSnifferData.protoInfo.strHeadLength+=arpSizeSize;
            tmpSnifferData.protoInfo.strHeadLength+="bytes";
            sprintf(arpSizeSize,"%u",arp_total_lenth);
            tmpSnifferData.protoInfo.strLength+=arpSizeSize;
            tmpSnifferData.protoInfo.strLength+="bytes";


            char arpSrcProtocolAddr[24],arpDstProtocolAddr[24];

            sprintf(arpSrcProtocolAddr,"%d.%d.%d.%d",arph->arp_spa[0],arph->arp_spa[1],arph->arp_spa[2],arph->arp_spa[3]);
            sprintf(arpDstProtocolAddr,"%d.%d.%d.%d",arph->arp_tpa[0],arph->arp_tpa[1],arph->arp_tpa[2],arph->arp_tpa[3]);

            if(htons(arph->arp_op)==1) {
                //request packet
                tmpSnifferData.protoInfo.strBasicInfo="Request:Who has";
                tmpSnifferData.protoInfo.strBasicInfo+=arpDstProtocolAddr;
                tmpSnifferData.protoInfo.strBasicInfo+=",tell";
                tmpSnifferData.protoInfo.strBasicInfo+=arpSrcProtocolAddr;
            }else if(htons(arph->arp_op)==2) {
                //reply packet
                tmpSnifferData.protoInfo.strBasicInfo="Reply:";
                tmpSnifferData.protoInfo.strBasicInfo+=arpSrcProtocolAddr;
                tmpSnifferData.protoInfo.strBasicInfo+="is at";
                tmpSnifferData.protoInfo.strBasicInfo+=tmpSnifferData.protoInfo.strSMac;

            } else {
                //LOG("there is something wrong with the arp packet")
            }

            tmpSnifferData.strSIP=arpSrcProtocolAddr;
            tmpSnifferData.strDIP=arpDstProtocolAddr;

            tmpSnifferData.protoInfo.strSIP+=arpSrcProtocolAddr;
            tmpSnifferData.protoInfo.strDIP+=arpDstProtocolAddr;

        } else {
            LOG("unknown proto");
        }

        sniffer->snifferData.push_back((tmpSnifferData));  //should send info to listview
        // send information to UI to showed in qlistview
        if(flag==1&&bstop==false) {
            emit sendSnifferInfoToUi(&tmpSnifferData);
        }
        LOG("emit");

        LOG((string)tmpSnifferData.strSIP.toStdString());
        LOG((string)tmpSnifferData.strDIP.toStdString());
        LOG((string)tmpSnifferData.strProto.toStdString());
        /*
         * above analyze udp and ip
         * push the results to sniffer->snifferdata;
         * then we have to send info to file
         */


    }


      //core function of capturing packets
      //add recursive code here.
}

