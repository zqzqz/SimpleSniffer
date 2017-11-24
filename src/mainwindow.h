#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "sniffer.h"
#include "networkchoice.h"
#include <unistd.h>
#include "capturethread.h"
#include "ui_mainwindow.h"
#include "QtWidgets/QMessageBox"
#include "QtWidgets/QFileDialog"
#include "filter.h"

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
    void on_pushButton_clicked();

    void on_start_clicked();

    void on_chooseNetButton_clicked();

    void quit();

    void save();

    void open();

    void about();

    void on_filter_textChanged(const QString &arg1);

    void on_filter_returnPressed();

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
};

#endif // MAINWINDOW_H
