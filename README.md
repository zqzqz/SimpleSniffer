# Linux Sniffer


## Dependency
* qt 5
* libpcap
* OS: linux

## Comments
Please do not push sniffer.pro.user anymore. Conflicts will happen.
Existing bug: When repeatly press start and stop without any packets captured, the code crashes at Csniffer::capture() sometimes.

## Code Structure
* NetworkChoice(Dialog) -- Sniffer
* FileDialog -- ListView
* MainWindow
  * CaptureThread
    * Sniffer
      * (inherit) CSniffer
  * Filter
  * MultiView
    * (inherit) ListView
  * SlideInfo

## Current tasks
* IP slides reunited (done)
* analyse file type which packets transmit (done)
* search and filtrate packets by protocal content (done)
* clicked right mouse on TreeView can save current packet info to file (done)
* analyse packets upon different protocols 
  * implement code in capturethread.cpp: run
  * show brief packets' info in List View (finished)
  * show detail in a tree structure (done)
  * show hex raw data in Text View (done)
* file operation
  * choose a file to save captured data (done)
  * load a file with packets' data  (done)
* packets filter (finished)
  * set standard rules and check user's input (finished)
  * filtrate packets with fixed rules (finished)
* using a dialog to choose network (finished)
  * dialog should show network info (finished)
  * user choose network in a list (finished)
  * press OK and network info should be passed to mainwindow (finished)
