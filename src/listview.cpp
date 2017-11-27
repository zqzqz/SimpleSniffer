#include "listview.h"

ListView::ListView(QTableView *v)
{
    index = 0;
    view = v;
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
}

ListView::~ListView()
{

}

void ListView::rebuildInfo()
{

}

void ListView::addPacketItem(QString strNum, QString strTime, QString strSIP,
                                        QString strDIP, QString strProto, QString strLength)
{
    QStandardItem *item;

    item = new QStandardItem(QString(strNum));
    mainModel->setItem(index, 0, item);
    item = new QStandardItem(QString(strTime));
    mainModel->setItem(index, 1, item);
    item = new QStandardItem(QString(strSIP));
    mainModel->setItem(index, 2, item);
    item = new QStandardItem(QString(strDIP));
    mainModel->setItem(index, 3, item);
    item = new QStandardItem(QString(strProto));
    mainModel->setItem(index, 4, item);
    item = new QStandardItem(QString(strLength));
    mainModel->setItem(index, 5, item);

    index++;
}

void ListView::getOrderNumber(QModelIndex &index, QString &strNumber)
{
    strNumber = mainModel->data(index, 0).toString();
}

bool ListView::isChanged()
{
    // Qt::MatchWildcard 使用基于字符串的通配符  Qt::MatchRecursive 搜索整个目录结构
    QList<QStandardItem *> tmp = mainModel->findItems("*", Qt::MatchWildcard | Qt::MatchRecursive);

    if (tmp.size() != 0) {
        return true;
    }

    return false;
}
