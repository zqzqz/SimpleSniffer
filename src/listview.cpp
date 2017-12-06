#include "listview.h"
#include <iostream>
ListView::ListView(QTableView *v)
{
    view = v;
    mainModel = new QStandardItemModel();
    mainModel->setHorizontalHeaderItem(0,new QStandardItem(QObject::tr("NO.")));
    mainModel->setHorizontalHeaderItem(1,new QStandardItem(QObject::tr("Time")));
    mainModel->setHorizontalHeaderItem(2,new QStandardItem(QObject::tr("Source IP")));
    mainModel->setHorizontalHeaderItem(3,new QStandardItem(QObject::tr("Destination IP")));
    mainModel->setHorizontalHeaderItem(4,new QStandardItem(QObject::tr("Protocol")));
    mainModel->setHorizontalHeaderItem(5,new QStandardItem(QObject::tr("Size")));


    view->setModel(mainModel);
    view->setColumnWidth(0,90);
    view->setColumnWidth(1,150);
    view->setColumnWidth(2,200);
    view->setColumnWidth(3,200);
    view->setColumnWidth(4,200);
    view->setColumnWidth(5,90);

    view->horizontalHeader()->resizeSections(QHeaderView::ResizeMode::Fixed);
    view->verticalHeader()->hide();
    view->setSelectionBehavior(QAbstractItemView::SelectRows);
    view->setSelectionMode(QAbstractItemView::SingleSelection);
    view->setTextElideMode(Qt::ElideMiddle);
    view->setEditTriggers(QAbstractItemView::NoEditTriggers);

    index = 0;
}

ListView::~ListView()
{
    clearData();
}

/*
 * clear all data to init status
 *
 */
void ListView::clearData()
{
    packets.clear();
    status.clear();
    fileFlow.clear();
    index = 0;
    rebuildInfo();
}

/*
 * delete all items in tableView
 * vector<snifferdata> packets not changed
 */
void ListView::rebuildInfo()
{
    mainModel->clear();
    //set tableview
    mainModel = new QStandardItemModel();
    mainModel->setHorizontalHeaderItem(0,new QStandardItem(QObject::tr("NO.")));
    mainModel->setHorizontalHeaderItem(1,new QStandardItem(QObject::tr("Time")));
    mainModel->setHorizontalHeaderItem(2,new QStandardItem(QObject::tr("Source IP")));
    mainModel->setHorizontalHeaderItem(3,new QStandardItem(QObject::tr("Destination IP")));
    mainModel->setHorizontalHeaderItem(4,new QStandardItem(QObject::tr("Protocol")));
    mainModel->setHorizontalHeaderItem(5,new QStandardItem(QObject::tr("Size")));


    view->setModel(mainModel);
    view->setColumnWidth(0,90);
    view->setColumnWidth(1,150);
    view->setColumnWidth(2,200);
    view->setColumnWidth(3,200);
    view->setColumnWidth(4,200);
    view->setColumnWidth(5,90);

    view->horizontalHeader()->resizeSections(QHeaderView::ResizeMode::Fixed);
    view->verticalHeader()->hide();
    view->setSelectionBehavior(QAbstractItemView::SelectRows);
    view->setSelectionMode(QAbstractItemView::SingleSelection);
    view->setTextElideMode(Qt::ElideMiddle);
    view->setEditTriggers(QAbstractItemView::NoEditTriggers);

    index = 0;
}

/*
 * called by CaptureThread::run
 * add a new packet
 */
void ListView::addPacketItem(SnifferData &tmpSnifferData, bool fnew, bool display)
{
    if (display) {
        QStandardItem *item;

        item = new QStandardItem(QString(tmpSnifferData.strNum));
        mainModel->setItem(index, 0, item);
        item = new QStandardItem(QString(tmpSnifferData.strTime));
        mainModel->setItem(index, 1, item);
        item = new QStandardItem(QString(tmpSnifferData.strSIP));
        mainModel->setItem(index, 2, item);
        item = new QStandardItem(QString(tmpSnifferData.strDIP));
        mainModel->setItem(index, 3, item);
        item = new QStandardItem(QString(tmpSnifferData.strProto));
        mainModel->setItem(index, 4, item);
        item = new QStandardItem(QString(tmpSnifferData.strLength));
        mainModel->setItem(index, 5, item);

        //set color according to protocols
        QVariant qcolor;
        QColor* color;
        switch (tmpSnifferData.protoInfo.tcpFlag) {
        case(TCP_SIG): color = new QColor(100,255,100);break;
        case(UDP_SIG): color = new QColor(100,100,255);break;
        case(ICMP_SIG): color = new QColor(255,100,100);break;
        case(IGMP_SIG): color = new QColor(255,255,100);break;
        default: color = new QColor(200,200,200);
        }
        qcolor = *color;
        for (int i=0; i<6; i++) {
            //how to make it easier :(
            mainModel->setData(mainModel->index(index, i), qcolor, Qt::BackgroundRole);
        }
        delete color;
        index++;
    }

    if(fnew) packets.push_back(tmpSnifferData);
}

/*
 * add a packet which may contain file data to record
 *
 */
void ListView::addFilePacket(QString id, unsigned int seq, int index)
{
    std::vector< std::map<unsigned int, int> >::iterator miter;
    std::vector<QString>::iterator iter = std::find(status.begin(), status.end(), id);
    if (iter == status.end()) {
        status.push_back(id);
        std::map<unsigned int, int> newmap;
        newmap.insert(std::make_pair(seq, index));
        fileFlow.push_back(newmap);
    }
    else {
        miter = fileFlow.begin() + (iter - status.begin());
        (*miter).insert(std::make_pair(seq, index));
    }
}


void ListView::loadByIndex(std::vector<int> &indexs)
{
    rebuildInfo();
    for(std::vector<int>::iterator it = indexs.begin(); it != indexs.end(); it++) {
        addPacketItem(packets.at(*it), false, true);
    }
}

/*
 * forget to use :)
 */
void ListView::getOrderNumber(QModelIndex &index, QString &strNumber)
{
    strNumber = mainModel->data(index, 0).toString();
}

int ListView::getPacketsNum()
{
    return packets.size();
}
/*
 * unused
 *
 */
bool ListView::isChanged()
{
    // Qt::MatchWildcard 使用基于字符串的通配符  Qt::MatchRecursive 搜索整个目录结构
    QList<QStandardItem *> tmp = mainModel->findItems("*", Qt::MatchWildcard | Qt::MatchRecursive);

    if (tmp.size() != 0) {
        return true;
    }

    return false;
}
