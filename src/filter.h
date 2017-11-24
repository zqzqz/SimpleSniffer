#ifndef FILTER_H
#define FILTER_H
#include "mainwindow.h"
#include "log.h"
#include <string.h>
#include <regex>
#include <map>

class Filter
{
public:
    Filter();
    ~Filter();
    bool checkCommand(QString command);
    bool filtrate(QString command, QListView* pListView);
    void printQuery(); //test

private:
    map<string, string> query;
    bool loadCommand(QString command);
    void launchFilter(QListView* pListView);
    string findWord(string com, size_t pos);

};

#endif // FILTER_H
