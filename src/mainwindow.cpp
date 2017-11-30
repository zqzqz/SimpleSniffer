#include "mainwindow.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    sniffer = new Sniffer();
    currentFile = "default.pcap";
    netDevDialog = new NetworkChoice(sniffer, this);
    snifferStatus = false;
    filter = new Filter();
    view = new MultiView(ui->treeView, ui->textBrowser, ui->tableView);
    //view= new ListView(ui->tableView);
    connect(ui->actionQuit, SIGNAL(triggered()), this, SLOT(quit()));
    connect(ui->actionSave, SIGNAL(triggered()), this, SLOT(save()));
    connect(ui->actionOpen, SIGNAL(triggered()), this, SLOT(open()));
    connect(ui->actionOurTeam, SIGNAL(triggered()), this, SLOT(about()));
    connect(ui->actionSaveTree, SIGNAL(triggered()), this, SLOT(saveTree()));

    //button settings
    ui->start->setIcon(QIcon(":/resource/button/start.png"));
    ui->start->setToolTip(tr("Start (Ctrl+S)"));

    //mainwindow appearance settings
    //setWindowTitle(tr("Sniffer - 1.0.0 Beta"));

    // choose network when app executing by default
    if(netDevDialog->exec() == QDialog::Accepted) {
        ui->netLabel->setText(sniffer->currentNetName);
    }

}

MainWindow::~MainWindow()
{
    delete ui;
    delete sniffer;
    delete filter;
}


/*
 * start capturing packets
 * unfinished; use threads in the future
 */
void MainWindow::on_start_clicked()
{
    if (! snifferStatus) {
        snifferStatus = true;
        view->clearData();
        //ui->start->setText(tr("Stop"));
        ui->start->setIcon(QIcon(":/resource/button/stop.png"));
        ui->start->setToolTip(tr("Stop (Ctrl+S)"));

        /* save to tmpfile,not set*/
        QDateTime nowTime=QDateTime::currentDateTime();
        QString tmpFileName=QDir::tempPath()+"/SimpleSniffer~"+nowTime.toString("yyyy-MM-dd~hh-mm-ss")+".tmp";

        LOG("WRONG2");

        pCaptureThread=new CaptureThread(sniffer, tmpFileName, view);

        //pCaptureThread->setCondition();
        pCaptureThread->start();
    }
    else {
        snifferStatus = false;
        ui->start->setIcon(QIcon(":/resource/button/start.png"));
        ui->start->setToolTip(tr("Start (Ctrl+S)"));
        pCaptureThread->stop();
    }

}

/*
 * handle the result of choose network Dialog
 * change the label if necessary.
 */
void MainWindow::on_chooseNetButton_clicked()
{
    if (netDevDialog->exec() == QDialog::Accepted) {
        sniffer->freeNetDevs();
        ui->netLabel->setText(sniffer->currentNetName);
    }
}

void MainWindow::quit()
{
    if ( QMessageBox::warning(this, tr("QUIT"), tr("<p>You are quiting the Sniffer.<p><p>Are you sure?</p>"), QMessageBox::Yes | QMessageBox::Cancel) == QMessageBox::Yes) {
        this->close();
    }
}

/*
 * funcion connected to label action 'Save'
 * save current file to a selected name. call saveFile.
 */
void MainWindow::save()
{
    QString saveFileName = QFileDialog::getSaveFileName(this, tr("Save As ... "), ".", tr("Sniffer captured data (*.pcap)"));
    if (!saveFileName.isEmpty()) {
        saveFile(saveFileName);
    }
}

bool MainWindow::saveFile(QString saveFileName)
{
    if (currentFile.isEmpty()) {
        return false;
    }
    if (!QFile::copy(currentFile, saveFileName)) {
        QMessageBox::warning(this, tr("Open As ... "), tr("<h3>ERROR Opening File</h3><p>A error occurs when opening the file.</p>"), QMessageBox::Ok);
        return false;
    }
    return false;
}

/*
 * funcion connected to label action 'Open'
 * Open a selected file as current file. call openFile.
 */
void MainWindow::open()
{
    QString saveFileName = QFileDialog::getOpenFileName(this, tr("Open ... "), ".", tr("Sniffer captured data (*.pcap)"));
    if (!saveFileName.isEmpty()) {
        if(openFile(saveFileName) == false) {
            QMessageBox::warning(this, tr("Open Error"),
                      tr("<h3>Open File Error</h3><p>Something wrong taken place when opening the file"));
        }
        else {
            changeFile(saveFileName);
        }
    }
}

bool MainWindow::openFile(QString openFileName)
{
    //load data here
    LOG(openFileName.toLatin1().data());
    return false;
}

bool MainWindow::changeFile(QString newFileName)
{
    sniffer->closeDumpFile();
    if (! sniffer->openDumpFile(newFileName.toLatin1().data())) {
        LOG("open file error");
        return false;
    }
    else {
        currentFile = newFileName;
    }
    return true;
}

void MainWindow::about()
{
    QMessageBox::about(this, tr("About Our Team"), tr("Collaborators: Zhengyu Yang & Qingzhao Zhang"));
}

/*
 * filter control functions
 * when text changes, check the syntax.
 * when RETURN pressed, launch the filter.
 */
void MainWindow::on_filter_textChanged(const QString &command)
{
    QPalette palette;
    if (filter->checkCommand(command)) {
        palette.setColor(QPalette::Base, Qt::green);
    }
    else {
        palette.setColor(QPalette::Base, Qt::red);
    }
    ui->filter->setPalette(palette);
}

void MainWindow::on_filter_returnPressed()
{
    filter->loadCommand(ui->filter->text());
    filter->printQuery();
    filter->launchFilter(view);
}

void MainWindow::showInfoInListView()
{
    //pass
}


void MainWindow::on_stop_clicked() {
    //pass
}

void MainWindow::on_tableView_clicked(const QModelIndex &index)
{
    view->packetInfoByIndex(index);
}

/*
 * right mouse clicked event
 * on TreeView: save current packet info to file
 */
void MainWindow::on_treeView_customContextMenuRequested(const QPoint &pos)
{
    QMenu *popMenu =new QMenu(this);

    popMenu->addAction(ui->actionSaveTree);
    popMenu->exec(QCursor::pos());

}

void MainWindow::saveTree()
{
    LOG("right mouse clicked in TreeView");
    QString saveFileName = QFileDialog::getSaveFileName(this, tr("Save Packet Info ... "), ".", tr("text file (*.txt)"));
    if (!saveFileName.isEmpty()) {
        QFile file(saveFileName);
        if(file.open(QIODevice::WriteOnly | QIODevice::Text)) //write text to file
        {
            QTextStream out(&file);
            QList<QStandardItem*> list = view->returnTreeItems();

            foreach (QStandardItem* item, list) {
                out << item->text();
                out << "\n";
            }

            file.close();
        }
    }
}
