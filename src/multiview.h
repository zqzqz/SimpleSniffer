/*
 * multiview.h
 * inherit ListView
 * Deal with QTreeView & HexView on mainwindow
 *   using an index passed from QTableView signal
 *   refresh detail info of packets
 */

#ifndef MULTIVIEW_H
#define MULTIVIEW_H

#include "listview.h"
#include <QTreeView>
#include <QTextBrowser>
#include <QString>

class MultiView : public ListView
{
private:
    QStandardItemModel *treeModel;
    QTreeView *treeView;
    QTextBrowser *textBrowser;
    void reload();
    void setTreeViewByIndex(SnifferData SnifferData);
    void setHexViewByIndex(SnifferData SnifferData);
public:
    MultiView(QTreeView *tree, QTextBrowser* hex, QTableView *list):ListView(list),treeView(tree),textBrowser(hex){
        reload();
    }
    ~MultiView();
    void packetInfoByIndex(QModelIndex index);   //call to update treeView $ hexView; responding signal list_item_clicked
};

#endif // MULTIVIEW_H
