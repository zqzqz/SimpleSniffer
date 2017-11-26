#ifndef FILTER_H
#define FILTER_H
#include "mainwindow.h"
#include "log.h"
#include <string.h>
#include <QTableView>
#include <regex>
#include <map>

class Filter
{
public:
    Filter();
    ~Filter();
    bool checkCommand(QString command);
    bool filtrate(QString command, QTableView* pTableView);
    void printQuery(); //test

private:
    map<string, string> query;
    bool loadCommand(QString command);
    void launchFilter(QTableView* pListView);
    string findWord(string com, size_t pos);

};

#endif // FILTER_H
