#ifndef CAPTURETHREAD_H
#define CAPTURETHREAD_H

#include <QThread>
#include "multiview.h"
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
    CaptureThread(Sniffer *psniffer, QString filename, MultiView *view);
    void stop();
    void run();
    void setCondition();
    bool getCondition();
private:
    volatile bool bstop;
    Sniffer *sniffer;
    QString filename;
    MultiView *view;
};

#endif // CAPTURETHREAD_H
