#include "networkchoice.h"
#include <QComboBox>
#include <QWidget>
#include "log.h"

NetworkChoice::NetworkChoice(Sniffer *snifferObj, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::NetworkChoice)
{
    ui->setupUi(this);
    sniffer = snifferObj;
    addNetDevs();
}

NetworkChoice::~NetworkChoice()
{
    delete ui;
}

/*
 * print detail info of current network interface in the textBox
 * Include IPv4 IPv6 and descriptions.
 */
void NetworkChoice::showCurrentNetInfo(const QString &netDevName) {
    ui->IPinfoView->addScrollBarWidget(ui->verticalScrollBar, Qt::AlignRight);
    for (std::vector<NetDevInfo>::iterator i = sniffer->netDevInfo.begin(); i<sniffer->netDevInfo.end(); i++) {
        if (netDevName == i->strNetDevname.data()) {
            ui->IPinfoView->clear();
            ui->IPinfoView->insertPlainText("IPv4 Family: ");
            ui->IPinfoView->insertPlainText(i->strIPV4FamilyName.data());
            ui->IPinfoView->insertPlainText("\nIPv4 Address: ");
            ui->IPinfoView->insertPlainText(i->strIPV4Addr.data());
            ui->IPinfoView->insertPlainText("\nIPv6 Family: ");
            ui->IPinfoView->insertPlainText(i->strIPV6FamilyName.data());
            ui->IPinfoView->insertPlainText("\nIPv6 Address: ");
            ui->IPinfoView->insertPlainText(i->strIPV6Addr.data());
            ui->IPinfoView->insertPlainText("\n Other Descriptions: ");
            ui->IPinfoView->insertPlainText(i->strNetDevDescribe.data());
        }
    }
}

/*
 * choiceBox activated action
 * print current net info
 */
void NetworkChoice::on_choiceBox_activated(const QString &netDevName)
{
    showCurrentNetInfo(netDevName);
}


/*
 * search available network interfaces and add them into comboBox
 * call when initialize the Dialog
 */
void NetworkChoice::addNetDevs()
{
    ui->choiceBox->setEditable(true);
    if (! sniffer->getNetDevInfo()) {
        LOG(" no network interfaces found");
        return;
    }
    std::vector<NetDevInfo>::iterator i;
    for (i = sniffer->netDevInfo.begin(); i<sniffer->netDevInfo.end(); i++) {
        ui->choiceBox->insertItem(-1, i->strNetDevname.data());
    }
    i = sniffer->netDevInfo.begin();
    showCurrentNetInfo(i->strNetDevname.data());
}



void NetworkChoice::on_buttonBox_clicked()
{
    sniffer->currentNetName = ui->choiceBox->currentText();
}
