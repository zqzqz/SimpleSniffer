#include "networkchoice.h"
#include "ui_networkchoice.h"
#include "sniffer.h"

NetworkChoice::NetworkChoice(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::NetworkChoice)
{
    ui->setupUi(this);
}

NetworkChoice::~NetworkChoice()
{
    delete ui;
}
