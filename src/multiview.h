#ifndef MULTIVIEW_H
#define MULTIVIEW_H

#include "listview.h"
#include <QTreeView>
#include <QTextBrowser>

class MultiView : public ListView
{
private:
    QTreeView *treeView;
    QTextBrowser *textBrowser;
public:
    MultiView(QTreeView *tree, QTextBrowser* hex, QTableView *list):ListView(list),treeView(tree),textBrowser(hex){}
};

#endif // MULTIVIEW_H
