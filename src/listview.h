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
#include <map>


class ListView
{

public:
    QTableView *view;
    ListView(QTableView *view);
    ~ListView();

    void rebuildInfo();
    bool isChanged();

    void addPacketItem(SnifferData &data, bool fnew=true, bool display=true);
    void loadByIndex(std::vector<int> &indexs);
    void getOrderNumber(QModelIndex &index, QString &strNumber);

    void clearData();
    void addFilePacket(QString id, unsigned int seq, int index);
protected:
    friend class Filter;
    friend class FileDialog;
    QStandardItemModel *mainModel;
    int index;
    std::vector<SnifferData> packets;
    std::vector< QString > status;
    std::vector< std::map<unsigned int, int> > fileFlow;
};


#endif // LISTVIEW_H
