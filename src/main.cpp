#include "mainwindow.h"
#include "networkchoice.h"
#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MainWindow w;
    NetworkChoice d(&w);
    w.show();
    d.show();
    return a.exec();
}
