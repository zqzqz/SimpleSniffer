#ifndef CAPTURETHREAD_H
#define CAPTURETHREAD_H

#include <QThread>

#include "type.h"
class Sniffer;
namespace Ui {
    class MainWindow;
}

class CaptureThread : public QThread
{
    Q_OBJECT
public:
    CaptureThread();
    CaptureThread(Sniffer *psniffer, QString filename, Ui::MainWindow *ui);
    void stop();
    void run();
    void setCondition();
    bool getCondition();
signals:
    void sendSnifferInfoToUi(SnifferData*);
private:
    volatile bool bstop;
    Sniffer *sniffer;
    QString filename;
    Ui::MainWindow *ui;
};

#endif // CAPTURETHREAD_H
