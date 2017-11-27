#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "csniffer.h"
#include "networkchoice.h"
#include "log.h"
#include <iostream>
#include <QtGui>
#include "capturethread.h"



MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    tableRow=0;
    sniffer = new Sniffer();
    netDevDialog = new NetworkChoice(sniffer, this);
    //choose network when app executing by default
    if(netDevDialog->exec() == QDialog::Accepted) {

        ui->netLabel->setText(sniffer->currentNetName);

    }

    //set tableview

    modelForTableView = new QStandardItemModel();
    modelForTableView->setHorizontalHeaderItem(0,new QStandardItem(QObject::tr("NO.")));
    modelForTableView->setHorizontalHeaderItem(1,new QStandardItem(QObject::tr("Source IP")));
    modelForTableView->setHorizontalHeaderItem(2,new QStandardItem(QObject::tr("Destination IP")));
    modelForTableView->setHorizontalHeaderItem(3,new QStandardItem(QObject::tr("Source MAC")));
    modelForTableView->setHorizontalHeaderItem(4,new QStandardItem(QObject::tr("Destination MAC")));
    modelForTableView->setHorizontalHeaderItem(5,new QStandardItem(QObject::tr("Protocol")));
    modelForTableView->setHorizontalHeaderItem(6,new QStandardItem(QObject::tr("INFO")));

    ui->tableView->setModel(modelForTableView);
    ui->tableView->setColumnWidth(0,90);
    ui->tableView->setColumnWidth(1,150);
    ui->tableView->setColumnWidth(2,150);
    ui->tableView->setColumnWidth(3,150);
    ui->tableView->setColumnWidth(4,150);
    ui->tableView->setColumnWidth(5,90);
    ui->tableView->setColumnWidth(6,150);

    ui->tableView->horizontalHeader()->resizeSections(QHeaderView::ResizeMode::Fixed);
    ui->tableView->verticalHeader()->hide();
    ui->tableView->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->tableView->setSelectionMode(QAbstractItemView::SingleSelection);
    ui->tableView->setTextElideMode(Qt::ElideMiddle);
    ui->tableView->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ui->tableView->setFixedWidth(90*2+150*5);


    //connect(pCaptureThread,SIGNAL(sendSnifferInfoToUi(SnifferData*)),this, SLOT(recieveSnifferInfoToUi(SnifferData*)));
    //LOG("CONNECT");

    ui->start->setEnabled(true);
    ui->stop->setEnabled(false);


    // there is some bug
    //connect(&pCaptureThread,SIGNAL(sendSnifferInfoToUi(SnifferData*)),this, SLOT(recieveSnifferInfoToUi(SnifferData*)));
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
    /*if (pCaptureThread!=NULL) {

        //disconnect(pCaptureThread,SIGNAL(CaptureThread::sendSnifferInfoToUi(SnifferData*)),this, SLOT(recieveSnifferInfoToUi(SnifferData*)));
        LOG("wrong");
        //delete pCaptureThread;
    }*/

    LOG("wrong1");

    //delete pCaptureThread;

    /* save to tmpfile,not set*/
    QDateTime nowTime=QDateTime::currentDateTime();
    QString tmpFileName=QDir::tempPath()+"/SimpleSniffer~"+nowTime.toString("yyyy-MM-dd~hh-mm-ss")+".tmp";

    LOG("WRONG2");

    pCaptureThread=new CaptureThread(sniffer,tmpFileName);


    LOG("pre connect");
    connect(pCaptureThread,SIGNAL(sendSnifferInfoToUi(SnifferData*)),this, SLOT(recieveSnifferInfoToUi(SnifferData*)));
    LOG("connected");


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
    LOG("prestop");
    pCaptureThread->stop();
    LOG("stop");
}

void MainWindow::recieveSnifferInfoToUi(SnifferData * snifferDataFromThread)
{

    char tmpTableRow[6];
    sprintf(tmpTableRow,"%d",tableRow+1);

    modelForTableView->setItem(tableRow,0,new QStandardItem(tmpTableRow));
    modelForTableView->setItem(tableRow,1,new QStandardItem(snifferDataFromThread->strSIP));
    modelForTableView->setItem(tableRow,2,new QStandardItem(snifferDataFromThread->strDIP));
    modelForTableView->setItem(tableRow,3,new QStandardItem(snifferDataFromThread->protoInfo.strSMac));
    modelForTableView->setItem(tableRow,4,new QStandardItem(snifferDataFromThread->protoInfo.strDMac));
    modelForTableView->setItem(tableRow,5,new QStandardItem(snifferDataFromThread->strProto));
    if(snifferDataFromThread->protoInfo.strBasicInfo=="") {
        modelForTableView->setItem(tableRow,6,new QStandardItem("NONE"));
    } else {
        modelForTableView->setItem(tableRow,6,new QStandardItem(snifferDataFromThread->protoInfo.strBasicInfo));
    }

    //ui->tableView->setModel(modelForTableView);
    tableRow++;
    LOG((string)snifferDataFromThread->strProto.toStdString());

}

