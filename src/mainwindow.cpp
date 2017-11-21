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
    netDevDialog = new NetworkChoice(sniffer, this);
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
    sniffer->openDumpFile("-");
    sniffer->captureOnce(); //test
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
