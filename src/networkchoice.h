#ifndef NETWORKCHOICE_H
#define NETWORKCHOICE_H

#include <QDialog>
#include "../src/sniffer.h"
#include "ui_networkchoice.h"

class NetworkChoice : public QDialog
{
    Q_OBJECT

public:
    explicit NetworkChoice(Sniffer *snifferObj, QWidget *parent = 0);
    ~NetworkChoice();

private slots:

    void on_choiceBox_activated(const QString &arg1);

    //void on_buttonBox_accepted();

    void on_buttonBox_clicked();



private:
    Ui::NetworkChoice *ui;
    void addNetDevs();
    void showCurrentNetInfo(const QString &netName);
    Sniffer *sniffer;
    std::vector<NetDevInfo>::iterator netIndex;
};

#endif // NETWORKCHOICE_H
