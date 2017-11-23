#ifndef PACKET_H
#define PACKET_H

#include "type.h"
#include <QTreeView>
#include <QListView>
#include <QTextBrowser>

class Packet
{
public:
    Packet();
    ~Packet();
    void setTreeView(QTreeView *pTreeView);
    void addListView(QListView *pListView);
    void setHexView(QTextBrowser *pHexView);
private:
    SnifferData snifferData;
    //other structs
};

#endif // PACKET_H
