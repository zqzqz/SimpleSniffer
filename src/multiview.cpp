#include "multiview.h"
#include <iostream>

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
    QStandardItem *item, *itemChild;
    QModelIndex index;

    item = new QStandardItem(snifferData.protoInfo.strEthTitle);
    treeModel->setItem(0, item);
    index = treeModel->item(0)->index();
    treeView->setExpanded(index, true);

    itemChild = new QStandardItem(snifferData.protoInfo.strDMac);
    item->appendRow(itemChild);
    itemChild = new QStandardItem(snifferData.protoInfo.strSMac);
    item->appendRow(itemChild);
    itemChild = new QStandardItem(snifferData.protoInfo.strType);
    item->appendRow(itemChild);

    item = new QStandardItem(snifferData.protoInfo.strNetTitle);
    treeModel->setItem(1, item);
    index = treeModel->item(1)->index();
    treeView->setExpanded(index, true);


/************************************network layer*******************************************/
    if((snifferData.strProto.toStdString())=="ARP") {
        itemChild = new QStandardItem(snifferData.protoInfo.strArpHard);
        item->appendRow(itemChild);
        itemChild = new QStandardItem(snifferData.protoInfo.strArpPro);
        item->appendRow(itemChild);
        itemChild = new QStandardItem(snifferData.protoInfo.strArpHardSize);
        item->appendRow(itemChild);
        itemChild = new QStandardItem(snifferData.protoInfo.strArpProSize);
        item->appendRow(itemChild);
        itemChild = new QStandardItem(snifferData.protoInfo.strOpCode);
        item->appendRow(itemChild);
        itemChild = new QStandardItem(snifferData.protoInfo.strSenderMac);
        item->appendRow(itemChild);
        itemChild = new QStandardItem(snifferData.protoInfo.strSIP);
        item->appendRow(itemChild);
        itemChild = new QStandardItem(snifferData.protoInfo.strTargetMac);
        item->appendRow(itemChild);
        itemChild = new QStandardItem(snifferData.protoInfo.strDIP);
        item->appendRow(itemChild);
        return;
    } else {
        itemChild = new QStandardItem(snifferData.protoInfo.strVersion);
        item->appendRow(itemChild);
        itemChild = new QStandardItem(snifferData.protoInfo.strHeadLength);
        item->appendRow(itemChild);
        itemChild = new QStandardItem(snifferData.protoInfo.strLength);
        item->appendRow(itemChild);
        itemChild = new QStandardItem(snifferData.protoInfo.strNextProto);
        item->appendRow(itemChild);
        itemChild = new QStandardItem(snifferData.protoInfo.strSIP);
        item->appendRow(itemChild);
        itemChild = new QStandardItem(snifferData.protoInfo.strDIP);
        item->appendRow(itemChild);

    }





/*******************************************transport layer***********************************************/
    snifferData.protoInfo.strTranProto+=snifferData.strProtoForShow;
    item = new QStandardItem(snifferData.protoInfo.strTranProto);
    treeModel->setItem(2, item);
    index = treeModel->item(2)->index();
    treeView->setExpanded(index, true);


    if((snifferData.strProto.toStdString()).substr(0,3)=="TCP") {
        snifferData.protoInfo.strSPort="源端口: "+snifferData.protoInfo.strSPort;
        snifferData.protoInfo.strDPort="目的端口: "+snifferData.protoInfo.strDPort;
        itemChild = new QStandardItem(snifferData.protoInfo.strSPort);
        item->appendRow(itemChild);
        itemChild = new QStandardItem(snifferData.protoInfo.strDPort);
        item->appendRow(itemChild);
        itemChild = new QStandardItem(snifferData.protoInfo.strSeqNo);
        item->appendRow(itemChild);
        itemChild = new QStandardItem(snifferData.protoInfo.strAckNo);
        item->appendRow(itemChild);
        itemChild = new QStandardItem(snifferData.protoInfo.strWindowSize);
        item->appendRow(itemChild);
        itemChild = new QStandardItem(snifferData.protoInfo.strChkSum);
        item->appendRow(itemChild);
    } else if((snifferData.strProto.toStdString()).substr(0,3)=="UDP") {
        snifferData.protoInfo.strSPort="源端口: "+snifferData.protoInfo.strSPort;
        snifferData.protoInfo.strDPort="目的端口: "+snifferData.protoInfo.strDPort;
        itemChild = new QStandardItem(snifferData.protoInfo.strSPort);
        item->appendRow(itemChild);
        itemChild = new QStandardItem(snifferData.protoInfo.strDPort);
        item->appendRow(itemChild);
        itemChild = new QStandardItem(snifferData.protoInfo.strUdpLenth);
        item->appendRow(itemChild);
        itemChild = new QStandardItem(snifferData.protoInfo.strChkSum);
        item->appendRow(itemChild);

    } else if((snifferData.strProto.toStdString())=="ICMP") {
        itemChild = new QStandardItem(snifferData.protoInfo.strIcmpType);
        item->appendRow(itemChild);
        itemChild = new QStandardItem(snifferData.protoInfo.strIcmpCode);
        item->appendRow(itemChild);
        itemChild = new QStandardItem(snifferData.protoInfo.strChkSum);
        item->appendRow(itemChild);
        return;

    } else if((snifferData.strProto.toStdString())=="IGMP") {
        itemChild = new QStandardItem(snifferData.protoInfo.strIgmpType);
        item->appendRow(itemChild);
        itemChild = new QStandardItem(snifferData.protoInfo.strChkSum);
        item->appendRow(itemChild);
        return;
    } else {
        return; //pass
    }


/***********************************application layer****************************************************/

    item = new QStandardItem(snifferData.protoInfo.strAppProto);
    treeModel->setItem(3, item);
    index = treeModel->item(3)->index();
    treeView->setExpanded(index, true);
}

/*
 * called by MultiView::packetInfoByIndex
 * Display hexView
 */
void MultiView::setHexViewByIndex(SnifferData snifferData)
{
    QByteArray rawData = snifferData.strData;
    bool ok; int cnt = 0;
    QString data = rawData;
    QString byte;
    QString ascii = QObject::tr("");
    QString line = QObject::tr("");
    for (int i=17; i<data.length(); i = i+2) {
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
        }
    }

}


QList<QStandardItem*> MultiView::returnTreeItems()
{
    return treeModel->findItems(QObject::tr("*"), Qt::MatchWildcard | Qt::MatchRecursive);
}
