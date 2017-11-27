#ifndef LISTVIEW_H
#define LISTVIEW_H

#include <QTableView>
#include <QtGui>
#include <QHeaderView>
#include <QStandardItemModel>
#include <QModelIndex>
#include <QString>
#include <QStandardItem>


class ListView
{

public:
    QTableView *view;
    ListView(QTableView *view);
    ~ListView();

    void rebuildInfo();
    bool isChanged();

    void addPacketItem(QString strNum, QString strTime, QString strSIP,
                                QString strDIP, QString strProto, QString strLength);

    void getOrderNumber(QModelIndex &index, QString &strNumber);

private:
    QStandardItemModel *mainModel;
    int index;
};


#endif // LISTVIEW_H
