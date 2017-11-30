#ifndef FILTER_H
#define FILTER_H
#include "mainwindow.h"
#include "log.h"
#include <string.h>
#include <QTableView>
#include "multiview.h"
#include <regex>
#include <map>
#define P 0
#define S 1
#define D 2
#define SPORT 3
#define DPORT 4
#define C 5

class Filter
{
public:
    Filter();
    ~Filter();
    bool checkCommand(QString command);
    bool loadCommand(QString command);
    void launchFilter(MultiView* view);
    void printQuery(); //test

private:
    map<int, string> query;
    string findWord(string com, size_t pos);

};

#endif // FILTER_H
