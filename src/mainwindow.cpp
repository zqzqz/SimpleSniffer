#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "csniffer.h"
#include <iostream>

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    sniffer = new Sniffer();
}

MainWindow::~MainWindow()
{
    delete ui;
}


void MainWindow::on_pushButton_clicked()
{

}
void MainWindow::on_start_clicked()
{

    //std::cout<<sniffer->err<<endl;
    sniffer->getNetDevInfo();
    char netname[10]="enp0s3";
    sniffer->openNetDev(netname);
    sniffer->openDumpFile("-");
    sniffer->capture();
    sniffer->testPrint();
}
