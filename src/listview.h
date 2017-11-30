/*
 * listview.h
 * Deal with QTableView on  mainwindow:
 *   collect snifferData from captureThread
 *   add Items into TableView
 */
#ifndef LISTVIEW_H
#define LISTVIEW_H

#include <QTableView>
#include <QtGui>
#include <QHeaderView>
#include <QStandardItemModel>
#include <QModelIndex>
#include <QString>
#include <QStandardItem>
#include <QByteArray>
#include "type.h"
#include <vector>


class ListView
{

public:
    QTableView *view;
    ListView(QTableView *view);
    ~ListView();

    void rebuildInfo();
    bool isChanged();

    void addPacketItem(SnifferData &data, bool fnew=true);

    void getOrderNumber(QModelIndex &index, QString &strNumber);

    void clearData();
protected:
    friend class Filter;
    QStandardItemModel *mainModel;
    int index;
    std::vector<SnifferData> packets;
};


#endif // LISTVIEW_H
