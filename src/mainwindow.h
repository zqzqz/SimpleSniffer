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
    void on_pushButton_clicked();

    void on_start_clicked();

    void on_chooseNetButton_clicked();

    void quit();

    void save();

    void open();

    void about();

private:
    Ui::MainWindow *ui;
    Sniffer *sniffer;
    NetworkChoice *netDevDialog;
    CaptureThread *captureThread;
    QString currentFile;
    bool saveFile(QString saveFileName);
    bool openFile(QString openFileName);
};

#endif // MAINWINDOW_H
