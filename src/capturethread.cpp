#include "capturethread.h"
#include "sniffer.h"

namespace Ui {
    class MainWindow;
}
CaptureThread::CaptureThread()
{

}

CaptureThread::CaptureThread(Sniffer *psniffer, QString tmpfilename, Ui::MainWindow *window)
{
    bstop = false;
    sniffer = psniffer;
    filename = tmpfilename;
    ui = window;
}

void CaptureThread::stop()
{
    bstop = true;
}

void CaptureThread::run()
{
    //core function of capturing packets
    //add recursive code here.
}
