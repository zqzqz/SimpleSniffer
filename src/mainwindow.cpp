#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "csniffer.h"
#include "networkchoice.h"
#include "log.h"
#include <iostream>

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    sniffer = new Sniffer();
    currentFile = "default.pcap";
    netDevDialog = new NetworkChoice(sniffer, this);
    connect(ui->actionQuit, SIGNAL(triggered()), this, SLOT(quit()));
    connect(ui->actionSave, SIGNAL(triggered()), this, SLOT(save()));
    connect(ui->actionOpen, SIGNAL(triggered()), this, SLOT(open()));
    connect(ui->actionOurTeam, SIGNAL(triggered()), this, SLOT(about()));
    // choose network when app executing by default
    if(netDevDialog->exec() == QDialog::Accepted) {
        ui->netLabel->setText(sniffer->currentNetName);
    }
}

MainWindow::~MainWindow()
{
    delete ui;
}

/*
 * bug
 */
void MainWindow::on_pushButton_clicked()
{
    //pass
}

/*
 * start capturing packets
 * unfinished; use threads in the future
 */
void MainWindow::on_start_clicked()
{
    sniffer->openNetDev(sniffer->currentNetName.toLatin1().data());
    sniffer->openDumpFile(currentFile.toLatin1().data());
    sniffer->captureOnce(); //test
    sniffer->saveCaptureData();
    //captureThread = new CaptureThread(sniffer, filename, ui);
    //captureThread->run();
}

/*
 * handle the result of choose network Dialog
 * change the label if necessary.
 */
void MainWindow::on_chooseNetButton_clicked()
{
    if (netDevDialog->exec() == QDialog::Accepted) {
        ui->netLabel->setText(sniffer->currentNetName);
    }
}

void MainWindow::quit()
{
    if ( QMessageBox::warning(this, tr("QUIT"), tr("<p>You are quiting the Sniffer.<p><p>Are you sure?</p>"), QMessageBox::Yes | QMessageBox::Cancel) == QMessageBox::Yes) {
        this->close();
    }
}

void MainWindow::save()
{
    QString saveFileName = QFileDialog::getSaveFileName(this, tr("Save As ... "), ".", tr("Sniffer captured data (*.pcap)"));
    if (!saveFileName.isEmpty()) {
        saveFile(saveFileName);
    }
}

bool MainWindow::saveFile(QString saveFileName)
{
    return false;
}

void MainWindow::open()
{
    QString saveFileName = QFileDialog::getOpenFileName(this, tr("Open ... "), ".", tr("Sniffer captured data (*.pcap)"));
    if (!saveFileName.isEmpty()) {
        if(openFile(saveFileName) == false) {
            QMessageBox::warning(this, tr("Open Error"),
                      tr("<h3>Open File Error</h3><p>Something wrong taken place when opening the file"));
        }
    }
}

bool MainWindow::openFile(QString openFileName)
{
    return false;
}

void MainWindow::about()
{
    QMessageBox::about(this, tr("About Our Team"), tr("Collaborators: Zhengyu Yang & Qingzhao Zhang"));
}

