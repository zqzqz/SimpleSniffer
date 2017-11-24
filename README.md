# Linux Sniffer (homework)


## Dependency
* qt 5
* libpcap
* OS: linux

## Comments
Unfinished

## Current tasks
* analyse packets upon different protocols
  * implement code in capturethread.cpp: run
  * show brief packets' info in List View
  * show detail in a tree structure
  * show hex raw data in Text View
* file operation
  * choose a file to save captured data (untested)
  * load a file with packets' data  (untested)
* packets filter
  * set standard rules and check user's input (finished)
  * filtrate packets with fixed rules
* using a dialog to choose network (finished)
  * dialog should show network info (finished)
  * user choose network in a list (finished)
  * press OK and network info should be passed to mainwindow (finished)
