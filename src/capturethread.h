#ifndef CAPTURETHREAD_H
#define CAPTURETHREAD_H

#include <QThread>
#include "type.h"
#include "filter.h"
#include "slideinfo.h"

class Sniffer;
namespace Ui {
    class MainWindow;
}

class CaptureThread : public QThread
{
    Q_OBJECT
public:
    CaptureThread();
    CaptureThread(Sniffer *psniffer, QString filename, MultiView *view, Filter *filter);
    void stop();
    void run();
    void setCondition();
    bool getCondition();
private:
    volatile bool bstop;
    Sniffer *sniffer;
    QString filename;
    MultiView *view;
    Filter *filter;
    SlideInfo *pslideInfo;
};

#endif // CAPTURETHREAD_H
