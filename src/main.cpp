#include "mainwindow.h"
#include "networkchoice.h"
#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MainWindow w;  //need a qmainwindow to initialize it?
    w.show();
    return a.exec();
}
