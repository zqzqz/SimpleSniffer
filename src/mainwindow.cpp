#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "csniffer.h"
#include "networkchoice.h"
#include "log.h"
#include <unistd.h>
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
    currentFile = "default.pcap";
    netDevDialog = new NetworkChoice(sniffer, this);
    snifferStatus = false;
    filter = new Filter();

    connect(ui->actionQuit, SIGNAL(triggered()), this, SLOT(quit()));
    connect(ui->actionSave, SIGNAL(triggered()), this, SLOT(save()));
    connect(ui->actionOpen, SIGNAL(triggered()), this, SLOT(open()));
    connect(ui->actionOurTeam, SIGNAL(triggered()), this, SLOT(about()));
    // choose network when app executing by default
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
    delete sniffer;
    delete filter;
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
    if (! snifferStatus) {
        snifferStatus = true;
        ui->start->setText(tr("Stop"));

        sniffer->openNetDev(sniffer->currentNetName.toLatin1().data());
        changeFile("default.pcap");

        for(int i=0; i<10; i++) {
            sniffer->captureOnce(); //test
            sniffer->saveCaptureData();
        }
    }
    else {
        snifferStatus = false;
        ui->start->setText(tr("Start"));
    }
    //captureThread = new CaptureThread(sniffer, filename, ui);
    //captureThread->run();
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
        sniffer->freeNetDevs();
        ui->netLabel->setText(sniffer->currentNetName);
    }
}

void MainWindow::quit()
{
    if ( QMessageBox::warning(this, tr("QUIT"), tr("<p>You are quiting the Sniffer.<p><p>Are you sure?</p>"), QMessageBox::Yes | QMessageBox::Cancel) == QMessageBox::Yes) {
        this->close();
    }
}

/*
 * funcion connected to label action 'Save'
 * save current file to a selected name. call saveFile.
 */
void MainWindow::save()
{
    QString saveFileName = QFileDialog::getSaveFileName(this, tr("Save As ... "), ".", tr("Sniffer captured data (*.pcap)"));
    if (!saveFileName.isEmpty()) {
        saveFile(saveFileName);
    }
}

bool MainWindow::saveFile(QString saveFileName)
{
    if (currentFile.isEmpty()) {
        return false;
    }
    if (!QFile::copy(currentFile, saveFileName)) {
        QMessageBox::warning(this, tr("Open As ... "), tr("<h3>ERROR Opening File</h3><p>A error occurs when opening the file.</p>"), QMessageBox::Ok);
        return false;
    }
    return false;
}

/*
 * funcion connected to label action 'Open'
 * Open a selected file as current file. call openFile.
 */
void MainWindow::open()
{
    QString saveFileName = QFileDialog::getOpenFileName(this, tr("Open ... "), ".", tr("Sniffer captured data (*.pcap)"));
    if (!saveFileName.isEmpty()) {
        if(openFile(saveFileName) == false) {
            QMessageBox::warning(this, tr("Open Error"),
                      tr("<h3>Open File Error</h3><p>Something wrong taken place when opening the file"));
        }
        else {
            changeFile(saveFileName);
        }
    }
}

bool MainWindow::openFile(QString openFileName)
{
    //load data here
    LOG(openFileName.toLatin1().data());
    return false;
}

bool MainWindow::changeFile(QString newFileName)
{
    sniffer->closeDumpFile();
    if (! sniffer->openDumpFile(newFileName.toLatin1().data())) {
        LOG("open file error");
        return false;
    }
    else {
        currentFile = newFileName;
    }
    return true;
}

void MainWindow::about()
{
    QMessageBox::about(this, tr("About Our Team"), tr("Collaborators: Zhengyu Yang & Qingzhao Zhang"));
}

/*
 * filter control functions
 * when text changes, check the syntax.
 * when RETURN pressed, launch the filter.
 */
void MainWindow::on_filter_textChanged(const QString &command)
{
    QPalette palette;
    if (filter->checkCommand(command)) {
        palette.setColor(QPalette::Base, Qt::green);
    }
    else {
        palette.setColor(QPalette::Base, Qt::red);
    }
    ui->filter->setPalette(palette);
}

void MainWindow::on_filter_returnPressed()
{
    filter->filtrate(ui->filter->text(), ui->listView);
    filter->printQuery();
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
    modelForTableView->setItem(tableRow,6,new QStandardItem("NONE"));
    //ui->tableView->setModel(modelForTableView);
    tableRow++;
    LOG((string)snifferDataFromThread->strProto.toStdString());

}

