#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "csniffer.h"
#include "networkchoice.h"
#include "log.h"
#include <iostream>
#include <QtGui>

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    sniffer = new Sniffer();
    netDevDialog = new NetworkChoice(sniffer, this);
    //choose network when app executing by default
    if(netDevDialog->exec() == QDialog::Accepted) {
        ui->netLabel->setText(sniffer->currentNetName);
    }
    ui->start->setEnabled(true);
    ui->stop->setEnabled(false);

    connect(&thread, SIGNAL(sendSnifferInfoToUi(SnifferData&)),
   this, SLOT(recieveSnifferInfoToUi(SnifferData&));
}

MainWindow::~MainWindow()
{
    delete ui;
}

/*
 * bug
 * I think we can delete on_pushButton_clicked

void MainWindow::on_pushButton_clicked()
{   
    //pass
}
*/

/*
 * start capturing packets
 * unfinished; use threads in the future
 */
void MainWindow::on_start_clicked()
{      
    if (pCaptureThread!=NULL) {
        delete pCaptureThread;
    }

    /* save to tmpfile,not set*/
    QDateTime nowTime=QDateTime::currentDateTime();
    QString tmpFileName=QDir::tempPath()+"/SimpleSniffer~"+nowTime.toString("yyyy-MM-dd~hh-mm-ss")+".tmp";

    pCaptureThread=new CaptureThread(sniffer,tmpFileName);
    //pCaptureThread->setCondition();
    pCaptureThread->start();
    ui->start->setEnabled(false);
    ui->stop->setEnabled(true);


    /*pCaptureThread->sniffer->openNetDev(pCaptureThread->sniffer->currentNetName.toLatin1().data());  //open net device
    pCaptureThread->sniffer->openDumpFile("-");
    pCaptureThread->sniffer->captureOnce(); //test
    */
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

void MainWindow::showInfoInListView()
{
    //pass
}

void MainWindow::on_stop_clicked()
{
    ui->start->setEnabled(true);//pass
    ui->stop->setEnabled(false);
    pCaptureThread->stop();

}

void MainWindow::recieveSnifferInfoToUi(SnifferData &)
{

}

