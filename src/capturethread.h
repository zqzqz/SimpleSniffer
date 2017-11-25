#ifndef CAPTURETHREAD_H
#define CAPTURETHREAD_H

#include <QThread>
#include "type.h"
class Sniffer;

class CaptureThread : public QThread
{
    Q_OBJECT
public:
    CaptureThread(Sniffer *psniffer, QString filename = "");
    void stop();
    void run();
    void setCondition();
    bool getCondition();
signals:
    void sendSnifferInfoToUi(SnifferData&);
private:
    volatile bool bstop;
    Sniffer *sniffer;
    QString filename;
};

#endif // CAPTURETHREAD_H
