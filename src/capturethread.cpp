#include "capturethread.h"
#include "sniffer.h"

CaptureThread::CaptureThread(Sniffer *psniffer, QString tmpfilename)
{
    bstop = false;
    sniffer = psniffer;
    filename = tmpfilename;
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
