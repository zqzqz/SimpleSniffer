#ifndef NETWORKCHOICE_H
#define NETWORKCHOICE_H

#include <QDialog>
#include "../src/sniffer.h"

namespace Ui {
    class NetworkChoice;
}

class NetworkChoice : public QDialog
{
    Q_OBJECT

public:
    explicit NetworkChoice(QWidget *parent = 0);
    ~NetworkChoice();

private slots:

private:
    Ui::NetworkChoice *ui;
    Sniffer *sniffer;
};

#endif // NETWORKCHOICE_H
