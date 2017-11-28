#include "listview.h"

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

void ListView::clearData()
{
    mainModel->clear();
    packets.clear();
}

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
void ListView::addPacketItem(SnifferData &tmpSnifferData, bool fnew)
{
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
    if(fnew) packets.push_back(tmpSnifferData);

    index++;
}

/*
 * forget to use :)
 */
void ListView::getOrderNumber(QModelIndex &index, QString &strNumber)
{
    strNumber = mainModel->data(index, 0).toString();
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
