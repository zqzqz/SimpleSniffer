#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "../src/sniffer.h"
#include "networkchoice.h"
#include <unistd.h>
#include "capturethread.h"
#include <QtGui>

namespace Ui {
    class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

private slots:
    //void on_pushButton_clicked();

    void on_start_clicked();

    void on_stop_clicked();

    void on_chooseNetButton_clicked();

    void showInfoInListView();

public slots:
    void recieveSnifferInfoToUi(SnifferData*);

private:
    Ui::MainWindow *ui;
    Sniffer *sniffer;
    NetworkChoice *netDevDialog;
    CaptureThread *pCaptureThread;
    QStandardItemModel *modelForTableView;
    int tableRow;
};

#endif // MAINWINDOW_H
