#include "multiview.h"
#include "log.h"

MultiView::~MultiView()
{
    //nothing
}

/*
 * entry function
 * get target SnifferData
 */
void MultiView::packetInfoByIndex(QModelIndex index)
{
    reload();
    int i = mainModel->data(mainModel->index(index.row(), 0)).toInt();//??

    SnifferData snifferData = packets.at(i-1);
    setHexViewByIndex(snifferData);
    setTreeViewByIndex(snifferData);
}

/*
 * clear treeView & hexView
 * ready for new target packet
 */
void MultiView::reload()
{
    treeModel = new QStandardItemModel;
    treeModel->setColumnCount(1);
    treeModel->setHeaderData(0, Qt::Horizontal, QObject::tr("Captured Data: "));
    treeView->setModel(treeModel);
    textBrowser->clear();
}

/*
 * called by MultiView::packetInfoByIndex
 * Display treeView
 */
void MultiView::setTreeViewByIndex(SnifferData snifferData)
{
    QStandardItem *item, *itemChild, *itemSub;
    QModelIndex index;

    //preparation part
    QString sip = snifferData.strSIP.mid(0, snifferData.strSIP.indexOf(QObject::tr(":")));
    QString dip = snifferData.strDIP.mid(0, snifferData.strDIP.indexOf(QObject::tr(":")));


    /**********************   physical layer begin ***********************/
    item = new QStandardItem(QObject::tr("Ethereum II"));
    treeModel->setItem(0, item);
    index = treeModel->item(0)->index();
    //treeView->setExpanded(index, true);

    _eth_header* peth = (_eth_header*)snifferData.protoInfo.peth;

    QByteArray DMac,SMac;
    DMac.clear();SMac.clear();
    DMac.setRawData((const char *)peth->dstmac,6);
    SMac.setRawData((const char *)peth->srcmac,6);
    DMac=DMac.toHex().toUpper();
    SMac=SMac.toHex().toUpper();
    QString smac,dmac;
    smac =QObject::tr("")+SMac[0]+SMac[1]+QObject::tr("-")+SMac[2]+SMac[3]+QObject::tr("-")+SMac[4]+SMac[5]+QObject::tr("-")+SMac[6]+SMac[7]+QObject::tr("-")+SMac[8]+SMac[9]+QObject::tr("-")+SMac[10]+SMac[11];
    dmac =QObject::tr("")+DMac[0]+DMac[1]+QObject::tr("-")+DMac[2]+DMac[3]+QObject::tr("-")+DMac[4]+DMac[5]+QObject::tr("-")+DMac[6]+DMac[7]+QObject::tr("-")+DMac[8]+DMac[9]+QObject::tr("-")+DMac[10]+DMac[11];

    itemChild = new QStandardItem(QObject::tr("Destination: ")+dmac);
    item->appendRow(itemChild);
    itemChild = new QStandardItem(QObject::tr("Source: ")+smac);
    item->appendRow(itemChild);


    switch (htons(peth->eth_type)) {
    case(EPT_IP): {
        itemChild = new QStandardItem(QObject::tr("Ethernet Type: IPV4 (0x0800)"));
        item->appendRow(itemChild);
        break;
    }
    case(EPT_ARP): {
        itemChild = new QStandardItem(QObject::tr("Ethernet Type: Address Resolution Protocol (0x0806)"));
        item->appendRow(itemChild);
        break;
    }
    case(EPT_IP6): {
        itemChild = new QStandardItem(QObject::tr("Ethernet Type: IPV6 (0x86dd)"));
        item->appendRow(itemChild);
        break;
    }
    default: return;
    }

    /**********************   physical layer end ***********************/
    /**********************   transmission layer begin ***********************/

    switch (snifferData.protoInfo.ipFlag) {
    case(EPT_IP): {
        item = new QStandardItem(QObject::tr("Internet Protocol"));
        treeModel->setItem(1, item);
        index = treeModel->item(1)->index();
        //treeView->setExpanded(index, true);

        _ip_header* iph = (_ip_header*) snifferData.protoInfo.pip;
        itemChild = new QStandardItem(QObject::tr("Version: ")+QString::number((iph->ver_ihl & 0xF0)/16, 10));
        item->appendRow(itemChild);
        itemChild = new QStandardItem(QObject::tr("Header Length: ")+QString::number((iph->ver_ihl & 0x0F)*4, 10));
        item->appendRow(itemChild);
        itemChild = new QStandardItem(QObject::tr("Total Length: ")+QString::number(ntohs(iph->tlen), 10));
        item->appendRow(itemChild);
        itemChild = new QStandardItem(QObject::tr("Identification: 0x")+QString::number(ntohs(iph->identification), 16) +QObject::tr("  ")+ QString::number(ntohs(iph->identification), 10));
        item->appendRow(itemChild);
        itemSub = new QStandardItem(QObject::tr("Flags"));
        item->appendRow(itemSub);
        //treeView->setExpanded(itemSub->index(), true);
        itemChild = new QStandardItem(QObject::tr("Reserved Bit: ")+QString::number((ntohs(iph->flags_fo) & 0x8000)/128/256, 10));
        itemSub->appendRow(itemChild);
        itemChild = new QStandardItem(QObject::tr("Don't Fragment: ")+QString::number((ntohs(iph->flags_fo) & 0x4000)/64/256, 10));
        itemSub->appendRow(itemChild);
        itemChild = new QStandardItem(QObject::tr("More Fragment: ")+QString::number((ntohs(iph->flags_fo) & 0x2000)/32/256, 10));
        itemSub->appendRow(itemChild);
        itemChild = new QStandardItem(QObject::tr("Fragment Offset: ")+QString::number((ntohs(iph->flags_fo) & 0x1FFF), 10));
        item->appendRow(itemChild);
        itemChild = new QStandardItem(QObject::tr("Time to Live: ")+QString::number((iph->ttl), 10));
        item->appendRow(itemChild);
        itemChild = new QStandardItem(QObject::tr("Protocal: ")+snifferData.protoInfo.ipProto);
        item->appendRow(itemChild);
        itemChild = new QStandardItem(QObject::tr("Source: ")+sip);
        item->appendRow(itemChild);
        itemChild = new QStandardItem(QObject::tr("Destination: ")+dip);
        item->appendRow(itemChild);
        unsigned short ipOptionData;
        ipOptionData=iph->optionData;
        QString ipOptionDataType;
        if(((iph->ver_ihl & 0x0F)*4)>20) {

            switch (ipOptionData) {
            case 0:
                ipOptionDataType="End of Option List";
                break;
            case 1:
                ipOptionDataType="No Operation";
                break;
            case 130:
                ipOptionDataType="Security";
                break;
            case 131:
                ipOptionDataType="Loose Source and Record Route";
                break;
            case 137:
                ipOptionDataType="Strict Source and Record Route";
                break;
            case 7:
                ipOptionDataType="Record Route";
                break;
            case 136:
                ipOptionDataType="Stream Identifier";
                break;
            case 68:
                ipOptionDataType="Internet Timestamp";
                break;
            case 148:
                ipOptionDataType="Router Alert";
                break;
            default:
                ipOptionDataType="Unknow Option";
                break;
            }
        } else {
            ipOptionDataType="No Option";
        }
        itemChild = new QStandardItem(QObject::tr("Option Data: ")+ipOptionDataType);
        item->appendRow(itemChild);
        break;
    }
    case(EPT_ARP): {
        item = new QStandardItem(QObject::tr("Address Resolution Protocol"));
        treeModel->setItem(1, item);
        index = treeModel->item(1)->index();

        //treeView->setExpanded(index, true);

        _arp_header* arph = (_arp_header*) snifferData.protoInfo.pip;


        QByteArray arpDMac,arpSMac;
        arpDMac.clear();arpSMac.clear();
        arpDMac.setRawData((const char *)arph->arp_tha,6);
        arpSMac.setRawData((const char *)arph->arp_sha,6);
        arpDMac=arpDMac.toHex().toUpper();
        arpSMac=arpSMac.toHex().toUpper();
        QString arpsmac =QObject::tr("")+arpSMac[0]+arpSMac[1]+QObject::tr("-")+arpSMac[2]+arpSMac[3]+QObject::tr("-")+arpSMac[4]+arpSMac[5]+QObject::tr("-")+arpSMac[6]+arpSMac[7]+QObject::tr("-")+arpSMac[8]+arpSMac[9]+QObject::tr("-")+arpSMac[10]+arpSMac[11];
        QString arpdmac =QObject::tr("")+arpDMac[0]+arpDMac[1]+QObject::tr("-")+arpDMac[2]+arpDMac[3]+QObject::tr("-")+arpDMac[4]+arpDMac[5]+QObject::tr("-")+arpDMac[6]+arpDMac[7]+QObject::tr("-")+arpDMac[8]+arpDMac[9]+QObject::tr("-")+arpDMac[10]+arpDMac[11];



        itemChild = new QStandardItem(QObject::tr("Hardware Type: ")+QObject::tr("Ethernet (1)")); //fake
        item->appendRow(itemChild);
        itemChild = new QStandardItem(QObject::tr("Protocol Type: ")+QObject::tr("IPV4 (0x0800)")); //fake
        item->appendRow(itemChild);
        itemChild = new QStandardItem(QObject::tr("Hardware Size: ")+QString::number((arph->arp_hln), 10));
        item->appendRow(itemChild);
        itemChild = new QStandardItem(QObject::tr("Protocol Size: ")+QString::number((arph->arp_pln), 10));
        item->appendRow(itemChild);
        itemChild = new QStandardItem(QObject::tr("Opcode: ")+ ((htons(arph->arp_op)==0x0001)? QObject::tr("Request (1)"):QObject::tr("Reply (2)") ) );
        item->appendRow(itemChild);
        itemChild = new QStandardItem(QObject::tr("Sender MAC Address: ")+arpsmac);
        item->appendRow(itemChild);
        itemChild = new QStandardItem(QObject::tr("Sender IP Address: ")+sip);
        item->appendRow(itemChild);
        itemChild = new QStandardItem(QObject::tr("Target MAC Adress: ")+arpdmac);
        item->appendRow(itemChild);
        itemChild = new QStandardItem(QObject::tr("Target IP Adress: ")+dip);
        item->appendRow(itemChild);
    }
    case(EPT_IP6): {
        item = new QStandardItem(QObject::tr("Internet Protocol (IPv6)"));
        treeModel->setItem(1, item);
        index = treeModel->item(1)->index();
        //treeView->setExpanded(index, true);

        _ipv6_header* iph6 = (_ipv6_header*) snifferData.protoInfo.pip;
        itemChild = new QStandardItem(QObject::tr("Version: ")+QString::number(iph6->version, 10));
        item->appendRow(itemChild);
        itemChild = new QStandardItem(QObject::tr("Traffic Class: ")+QString::number(iph6->traffic, 10));
        item->appendRow(itemChild);
        itemChild = new QStandardItem(QObject::tr("Flow Label: 0x")+QString::number(ntohl(iph6->flow), 16));
        item->appendRow(itemChild);
        itemChild = new QStandardItem(QObject::tr("Payload Length: ")+QString::number(ntohs(iph6->pay_length), 10));
        item->appendRow(itemChild);
        itemChild = new QStandardItem(QObject::tr("Next Header: 0x")+QString::number(iph6->next_h, 16));
        item->appendRow(itemChild);
        itemChild = new QStandardItem(QObject::tr("Hop Limit: ")+QString::number(iph6->hop_limit, 10));
        item->appendRow(itemChild);
        itemChild = new QStandardItem(QObject::tr("Source: ")+sip);
        item->appendRow(itemChild);
        itemChild = new QStandardItem(QObject::tr("Destination: ")+dip);
        item->appendRow(itemChild);
        break;
    }
    default: return;
    }
    /**********************  transmission layer end ***********************/
    /**********************  network layer begin ***********************/

    switch(snifferData.protoInfo.tcpFlag){
    case(TCP_SIG): {
        item = new QStandardItem(QObject::tr("Transmission Control Protocol"));
        treeModel->setItem(2, item);
        index = treeModel->item(2)->index();
        //treeView->setExpanded(index, true);

        _tcp_header* tcph = (_tcp_header*) snifferData.protoInfo.ptcp;
        itemChild = new QStandardItem(QObject::tr("Source Port: ")+QString::number(ntohs(tcph->sport)));
        item->appendRow(itemChild);
        itemChild = new QStandardItem(QObject::tr("Destination Port: ")+QString::number(ntohs(tcph->dport), 10));
        item->appendRow(itemChild);
        itemChild = new QStandardItem(QObject::tr("Sequence Number: ")+QString::number(ntohl(tcph->seq_no), 10));
        item->appendRow(itemChild);
        itemChild = new QStandardItem(QObject::tr("Acknowledgment Number: ")+QString::number(ntohl(tcph->ack_no), 10));
        item->appendRow(itemChild);
        itemChild = new QStandardItem(QObject::tr("Header Length: ")+QString::number((tcph->thl & 0xF0)/4, 10));
        item->appendRow(itemChild);
        itemSub = new QStandardItem(QObject::tr("Flags"));
        item->appendRow(itemSub);
        itemChild = new QStandardItem(QObject::tr("Reserved: ")+QString::number((tcph->thl & 0x0E)/2, 10));
        itemSub->appendRow(itemChild);
        itemChild = new QStandardItem(QObject::tr("Nonce: ")+QString::number((tcph->thl & 0x01), 10));
        itemSub->appendRow(itemChild);
        itemChild = new QStandardItem(QObject::tr("CWR: ")+QString::number((tcph->flag & 0x80)/128, 10));
        itemSub->appendRow(itemChild);
        itemChild = new QStandardItem(QObject::tr("ECN-Echo: ")+QString::number((tcph->flag & 0x40)/64, 10));
        itemSub->appendRow(itemChild);
        itemChild = new QStandardItem(QObject::tr("Urgent: ")+QString::number((tcph->flag & 0x20)/32, 10));
        itemSub->appendRow(itemChild);
        itemChild = new QStandardItem(QObject::tr("ACK: ")+QString::number((tcph->flag & 0x10)/16, 10));
        itemSub->appendRow(itemChild);
        itemChild = new QStandardItem(QObject::tr("Push: ")+QString::number((tcph->flag & 0x8)/8, 10));
        itemSub->appendRow(itemChild);
        itemChild = new QStandardItem(QObject::tr("Reset: ")+QString::number((tcph->flag & 0x4)/4, 10));
        itemSub->appendRow(itemChild);
        itemChild = new QStandardItem(QObject::tr("Syn: ")+QString::number((tcph->flag & 0x2)/2, 10));
        itemSub->appendRow(itemChild);
        itemChild = new QStandardItem(QObject::tr("Fin: ")+QString::number((tcph->flag & 0x1), 10));
        itemSub->appendRow(itemChild);
        itemChild = new QStandardItem(QObject::tr("Win Size: ")+QString::number(ntohs(tcph->wnd_size), 10));
        item->appendRow(itemChild);
        itemChild = new QStandardItem(QObject::tr("Checksum: 0x")+QString::number(ntohs(tcph->chk_sum), 16));
        item->appendRow(itemChild);
        itemChild = new QStandardItem(QObject::tr("Urgent Pointer: ")+QString::number(tcph->urgt_p, 10));
        item->appendRow(itemChild);
        //itemSub = new QStandardItem(QObject::tr("Options"));
        //item->appendRow(itemSub);
        unsigned short tcpOption=tcph->tcpOptionData;
        QString tcpOptionType;
        if(((tcph->thl & 0xF0)/4)>20) {
            switch (tcpOption) {
            case 0:
                tcpOptionType="End Of Option List";
                break;
            case 1:
                tcpOptionType="No Operation";
                break;
            case 2:
                tcpOptionType="Maximum Segment Size";
                break;
            case 3:
                tcpOptionType="Window Scale";
                break;
            case 4:
                tcpOptionType="Selective ACK ok";
                break;
            case 5:
                tcpOptionType="Selective ACK";
                break;
            case 8:
                tcpOptionType="Timestamp";
                break;
            default:
                tcpOptionType="Unknow";
                break;
            }
            itemChild=new QStandardItem(QObject::tr("Option: ")+tcpOptionType);
            item->appendRow(itemChild);
        }

        //treeView->setExpanded(itemSub->index(), true);
        break;
    }
    case(UDP_SIG): {
        item = new QStandardItem(QObject::tr("User Datagram Protocol"));
        treeModel->setItem(2, item);
        index = treeModel->item(2)->index();
        //treeView->setExpanded(index, true);

        _udp_header* udph = (_udp_header*) snifferData.protoInfo.ptcp;
        itemChild = new QStandardItem(QObject::tr("Source Port: ")+QString::number(ntohs(udph->sport), 10));
        item->appendRow(itemChild);
        itemChild = new QStandardItem(QObject::tr("Destination Port: ")+QString::number(ntohs(udph->dport), 10));
        item->appendRow(itemChild);
        itemChild = new QStandardItem(QObject::tr("Length: ")+QString::number(ntohs(udph->len), 10));
        item->appendRow(itemChild);
        itemChild = new QStandardItem(QObject::tr("Checksum: 0x")+QString::number(ntohs(udph->crc), 16));
        item->appendRow(itemChild);
        break;
    }
    case(ICMP_SIG): {
        QString icmpType;
        item = new QStandardItem(QObject::tr("Internet Control Message Protocol"));
        treeModel->setItem(2, item);
        index = treeModel->item(2)->index();
        //treeView->setExpanded(index, true);

        _icmp_header* icmph = (_icmp_header*) snifferData.protoInfo.ptcp;
        switch(icmph->type) {
        case 8:
            icmpType = QObject::tr("(Echo (ping) request)");
            break;
        case 0:
            icmpType = QObject::tr("(Echo (ping) reply)");
            break;
        case 3:
            icmpType = QObject::tr("(Destination Unreachable)");
            break;
        case 4:
            icmpType = QObject::tr("(Source Quench)");
            break;
        case 5:
            icmpType = QObject::tr("(Redirect(Change route))");
            break;
        case 11:
            icmpType = QObject::tr("(Time Exceeded)");
            break;
        case 12:
            icmpType = QObject::tr("(Parameter Problem)");
            break;
        case 13:
            icmpType = QObject::tr("(Timestamp Request)");
            break;
        case 14:
            icmpType = QObject::tr("(Timestamp Reply)");
            break;
        case 15:
            icmpType = QObject::tr("(Information Request)");
            break;
        case 16:
            icmpType = QObject::tr("(Information Reply)");
            break;
        case 17:
            icmpType = QObject::tr("(Address Mask Request)");
            break;
        case 18:
            icmpType = QObject::tr("(Address Mask Reply)");
            break;
        default:
            break;
        }
        itemChild = new QStandardItem(QObject::tr("Type: ")+QString::number(icmph->type, 10)+QObject::tr("  ")+icmpType);
        item->appendRow(itemChild);
        itemChild = new QStandardItem(QObject::tr("Code: ")+QString::number(icmph->code, 10));
        item->appendRow(itemChild);
        itemChild = new QStandardItem(QObject::tr("Checksum: 0x")+QString::number(ntohs(icmph->crc), 16));
        item->appendRow(itemChild);
        break;
    }
    case(IGMP_SIG): {
        QString recordType;
        char ip[24];
        item = new QStandardItem(QObject::tr("Internet Group Management Protocol"));
        treeModel->setItem(2, item);
        index = treeModel->item(2)->index();
        //treeView->setExpanded(index, true);

        _igmp_header* igmph = (_igmp_header*) snifferData.protoInfo.ptcp;
        if (igmph->type == 0x22) {
            itemChild = new QStandardItem(QObject::tr("Type: Membership Report (0x22)"));
            item->appendRow(itemChild);
        }
        else {
            itemChild = new QStandardItem(QObject::tr("Type: Membership Query (0x11)"));
            item->appendRow(itemChild);
            itemChild = new QStandardItem(QObject::tr("Max Response Code: ") + QString::number((igmph->maxRespCode), 10));
            item->appendRow(itemChild);
            itemChild = new QStandardItem(QObject::tr("Checksum: ") + QString::number(ntohs(igmph->crc), 16));
            item->appendRow(itemChild);
            sprintf(ip, "%d.%d.%d.%d", igmph->groupAddress[0], igmph->groupAddress[1], igmph->groupAddress[2], igmph->groupAddress[3]);
            itemChild = new QStandardItem(QObject::tr("Multicast Address: ") + QString(QLatin1String(ip)));
            item->appendRow(itemChild);
        }
        /*
        itemChild = new QStandardItem(QObject::tr("Max Response Code: ") + QString::number((igmph->maxRespCode), 10));
        item->appendRow(itemChild);
        itemChild = new QStandardItem(QObject::tr("Checksum: ") + QString::number(ntohs(igmph->crc), 16));
        item->appendRow(itemChild);
        itemChild = new QStandardItem(QObject::tr("Num Group Record: ") + QString::number(igmph->numberOfGroupSrc));
        item->appendRow(itemChild);
        itemSub = new QStandardItem(QObject::tr("Group Record"));
        item->appendRow(itemSub);
        //treeView->setExpanded(itemSub->index(), true);

        switch(igmph->recordType) {
        case(1): recordType = QObject::tr("Include");break;
        case(2): recordType = QObject::tr("Exclude");break;
        case(3): recordType = QObject::tr("Leave Group");break;
        case(4): recordType = QObject::tr("Join Group");
        }
        itemChild = new QStandardItem(QObject::tr("Record Type: ")+recordType);
        itemSub->appendRow(itemChild);
        itemChild = new QStandardItem(QObject::tr("Aux Data Len: ") + QString::number(igmph->auxDataLen, 10));
        itemSub->appendRow(itemChild);
        itemChild = new QStandardItem(QObject::tr("Num Src: ") + QString::number(igmph->numberOfSrc, 10));
        itemSub->appendRow(itemChild);
        sprintf(ip, "%d.%d.%d.%d", igmph->groupAddress[0], igmph->groupAddress[1], igmph->groupAddress[2], igmph->groupAddress[3]);
        itemChild = new QStandardItem(QObject::tr("Multicast Address: ") + QString(QLatin1String(ip)));
        itemSub->appendRow(itemChild);
        */
        break;
    }
    default: return;
    }
    /************************* network layer end ********************************/
    /************************* application layer begin *****************************/
    QString appPro;
    switch(snifferData.protoInfo.appFlag) {
    case(FTP_PORT): appPro = QObject::tr("FTP(File Transfer Protocol)");break;
    case(TELNET_PORT): appPro = QObject::tr("TELNET");break;
    case(SMTP_PORT): appPro = QObject::tr("SMTP(Simple Message Transfer Protocol)");break;
    case(POP3_PORT): appPro = QObject::tr("POP3 (Post Office Protocol 3)");break;
    case(HTTPS_PORT): appPro = QObject::tr("HTTPS (Hypertext Transfer Protocol over Secure Socket Layer)");break;
    case(HTTP_PORT): appPro = QObject::tr("HTTP (Hyper Text Transport Protocol)");break;
    case(DNS_PORT): appPro = QObject::tr("DNS (Domain Name Server)");break;
    case(SNMP_PORT): appPro = QObject::tr("SNMP (Simple Network Management Protocol)");break;
    default: appPro = QObject::tr("TCP payload");
    }
    item = new QStandardItem(appPro);
    treeModel->setItem(3, item);
    index = treeModel->item(3)->index();
    //treeView->setExpanded(index, true);
    itemChild = new QStandardItem(QObject::tr("Data: ") + QString(snifferData.protoInfo.strSendInfo.toHex()));
    item->appendRow(itemChild);
}


/*
 * called by MultiView::packetInfoByIndex
 * Display hexView
 */
void MultiView::setHexViewByIndex(SnifferData snifferData)
{
    QByteArray rawData = snifferData.strData.toHex().toUpper();
    bool ok; int cnt = 0;
    QString data = rawData;
    QString byte;
    QString ascii = QObject::tr("");
    QString line = QObject::tr("");
    for (int i=0; i<data.length(); i = i+2) {    //from 17
        cnt += 1;
        byte = QObject::tr("");
        byte.append(data[i]);
        byte.append(data[i+1]);
        int asc = byte.toInt(&ok, 16);
        ascii.append((asc>32 && asc<127) ? char(asc) : '.');
        line.append(byte);
        line.append(" ");
        if (cnt%8 == 0) {
            line.append("  ");
            line.append(ascii);
            line.append("\n");
            textBrowser->insertPlainText(line);
            line = QObject::tr("");
            ascii = QObject::tr("");
        } else if(cnt==((data.length())/2)) {    //length-17
            for(int j=0;j<25-3*(cnt%8);j++) {
                line.append("  ");
            }
            line.append(ascii);
            textBrowser->insertPlainText(line);
            line = QObject::tr("");
            ascii = QObject::tr("");
        }
    }

}

QList<QStandardItem*> MultiView::returnTreeItems()
{
    return treeModel->findItems(QObject::tr("*"), Qt::MatchWildcard | Qt::MatchRecursive);
}
