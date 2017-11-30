#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "sniffer.h"
#include <unistd.h>
#include "capturethread.h"
#include "QtWidgets/QMessageBox"
#include "QtWidgets/QFileDialog"
#include "multiview.h"
#include "filter.h"
#include "ui_mainwindow.h"
#include "networkchoice.h"
#include "log.h"
#include <unistd.h>
#include <QTreeWidgetItem>
#include "capturethread.h"

namespace Ui {
    class MainWindow;
}
class Filter;

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

    void quit();

    void save();

    void open();

    void about();

    void saveTree();

    void on_filter_textChanged(const QString &arg1);

    void on_filter_returnPressed();
    void showInfoInListView();

    void on_tableView_clicked(const QModelIndex &index);

    void on_treeView_customContextMenuRequested(const QPoint &pos);

private:
    Ui::MainWindow *ui;
    Sniffer *sniffer;
    QString currentFile;
    NetworkChoice *netDevDialog;
    CaptureThread *captureThread;
    Filter *filter;
    bool snifferStatus; //true for running; false for stopped;

    bool saveFile(QString saveFileName);
    bool openFile(QString openFileName);
    bool changeFile(QString newFileName);
    CaptureThread *pCaptureThread;
    MultiView *view;
};

#endif // MAINWINDOW_H
