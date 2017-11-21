#ifndef CAPTURETHREAD_H
#define CAPTURETHREAD_H

#include <QThread>
class Sniffer;

class CaptureThread : public QThread
{
    Q_OBJECT
public:
    CaptureThread(Sniffer *psniffer, QString filename = "");
    void stop();
    void run();
private:
    volatile bool bstop;
    Sniffer *sniffer;
    QString filename;
};

#endif // CAPTURETHREAD_H
