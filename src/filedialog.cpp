#include "filedialog.h"
#include <QFileDialog>
#include "log.h"

FileDialog::FileDialog(MultiView *v, QWidget *parent): QDialog(parent), ui(new Ui::FileDialog), view(v)
{
    ui->setupUi(this);
    choice.clear();

    model = new QStandardItemModel();
    model->setHorizontalHeaderItem(0,new QStandardItem(QObject::tr("ID")));
    model->setHorizontalHeaderItem(1,new QStandardItem(QObject::tr("Type")));
    model->setHorizontalHeaderItem(2,new QStandardItem(QObject::tr("Size")));
    model->setHorizontalHeaderItem(3,new QStandardItem(QObject::tr("Packets")));

    ui->fileView->setModel(model);
    ui->fileView->setColumnWidth(0,60);
    ui->fileView->setColumnWidth(1,100);
    ui->fileView->setColumnWidth(2,100);
    ui->fileView->setColumnWidth(3,100);

    ui->fileView->horizontalHeader()->resizeSections(QHeaderView::ResizeMode::Fixed);
    ui->fileView->verticalHeader()->hide();
    ui->fileView->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->fileView->setSelectionMode(QAbstractItemView::SingleSelection);
    ui->fileView->setTextElideMode(Qt::ElideMiddle);
    ui->fileView->setEditTriggers(QAbstractItemView::NoEditTriggers);

}

FileDialog::~FileDialog()
{
    delete ui;
}

/*
 * init the status of dialog
 */
void FileDialog::prepare()
{
    ui->fileTypeBox->setCurrentIndex(0);
    choice.clear();
    filtrateFile();
    displayFile();
}

/*
 * filtrate possible files
 * now only *.png for test
 */
void FileDialog::filtrateFile()
{
    int id = 0;
    for (std::vector< std::map<unsigned int, int> >::iterator it = view->fileFlow.begin(); it<view->fileFlow.end(); it++) {
        // find the smallest seq as start
        std::map<unsigned int, int>::iterator mit = it->begin();
        QString name;
        unsigned int seq = mit->first;
        int index = mit->second;
        SnifferData snifferData = view->packets.at(index);
        QByteArray payload = snifferData.protoInfo.strSendInfo;

        //analyse file type by common file headers
        if (payload.indexOf(QByteArray::fromHex("89504e47")) ==0) {
            name = QString::number(id, 10) + tr(":png"); //test a png file
        }
        else if (payload.indexOf(QByteArray::fromHex("d0cf11e0a1b11ae1")) ==0) {
            name = QString::number(id, 10) + tr(":doc"); //test a doc file
        }
        else if (payload.indexOf(QByteArray::fromHex("ffd8ff")) ==0) {
            name = QString::number(id, 10) + tr(":jpg"); //test a jpg file
        }
        else if (payload.indexOf(QByteArray::fromHex("47494638")) ==0) {
            name = QString::number(id, 10) + tr(":gif"); //test a gif file
        }
        else if (payload.indexOf(QByteArray::fromHex("504B0304")) ==0) {
            name = QString::number(id, 10) + tr(":zip"); //test a zip file
        }
        else if (payload.indexOf(QByteArray::fromHex("52617221")) ==0) {
            name = QString::number(id, 10) + tr(":rar"); //test a rar file
        }
        else if (payload.indexOf(QByteArray::fromHex("41564920")) ==0) {
            name = QString::number(id, 10) + tr(":avi"); //test a avi file
        }
        else if (payload.indexOf(QByteArray::fromHex("68746D6C3E")) ==0) {
            name = QString::number(id, 10) + tr(":html"); //test a html file
        }
        else if (payload.indexOf(QByteArray::fromHex("255044462D312E")) ==0) {
            name = QString::number(id, 10) + tr(":pdf"); //test a pdf file
        }
        else {
            continue;
        }
        std::vector<int> indexs; indexs.push_back(index);


        while (true) {
            //calculate next seq
            snifferData = view->packets.at(index);
            _ip_header* iph = (_ip_header*) snifferData.protoInfo.pip;
            _tcp_header* tcph = (_tcp_header*) snifferData.protoInfo.ptcp;
            seq += (unsigned int)((ntohs(iph->tlen) - ntohs(iph->ver_ihl & 0x0F)/64- ntohs(tcph->thl & 0xF0)/16/64));
            //find next packet by seq
            mit = it->find(seq);
            if (mit == it->end()) break; //end
            else {
                index = mit->second;
                indexs.push_back(index);
            }
        }
        id++;
        files.insert(std::make_pair(name, indexs));
    }
}

/*
 * show file info in fileDialog's tableView
 *
 */
void FileDialog::displayFile()
{
    rebuild();
    QStandardItem *item;
    int index=0;
    for (std::map<QString, std::vector<int> >::iterator it = files.begin(); it != files.end(); it++) {
        item = new QStandardItem(it->first.left(it->first.indexOf(":")));
        model->setItem(index, 0, item);
        item = new QStandardItem(it->first.right(it->first.size() - it->first.indexOf(":") - 1));
        model->setItem(index, 1, item);
        item = new QStandardItem(tr("unknown"));
        model->setItem(index, 2, item);
        item = new QStandardItem(QString::number(it->second.size(), 10));
        model->setItem(index, 3, item);
        index++;
    }
}

void FileDialog::rebuild()
{
    model->clear();
    model = new QStandardItemModel();
    model->setHorizontalHeaderItem(0,new QStandardItem(QObject::tr("ID")));
    model->setHorizontalHeaderItem(1,new QStandardItem(QObject::tr("Type")));
    model->setHorizontalHeaderItem(2,new QStandardItem(QObject::tr("Size")));
    model->setHorizontalHeaderItem(3,new QStandardItem(QObject::tr("Packets")));

    ui->fileView->setModel(model);
    ui->fileView->setColumnWidth(0,60);
    ui->fileView->setColumnWidth(1,100);
    ui->fileView->setColumnWidth(2,100);
    ui->fileView->setColumnWidth(3,100);

    ui->fileView->horizontalHeader()->resizeSections(QHeaderView::ResizeMode::Fixed);
    ui->fileView->verticalHeader()->hide();
    ui->fileView->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->fileView->setSelectionMode(QAbstractItemView::SingleSelection);
    ui->fileView->setTextElideMode(Qt::ElideMiddle);
    ui->fileView->setEditTriggers(QAbstractItemView::NoEditTriggers);
}

void FileDialog::on_fileView_clicked(const QModelIndex &index)
{
    QString name = model->data(model->index(index.row(),0)).toString()+QObject::tr(":")+model->data(model->index(index.row(),1)).toString();
    choice.clear();
    choice.push_back(name);
    targetFileIndex = index;
}

/*
 * press OK in fileDialog means displaying packets which transmit selected files
 *
 */
void FileDialog::on_buttonBox_accepted()
{
    std::vector<int> indexs;
    for (std::vector<QString>::iterator it = choice.begin(); it!=choice.end(); it++) {
        std::map<QString, std::vector<int> >::iterator mit = files.find(*it);
        if (mit == files.end()) continue;
        for (std::vector<int>::iterator indexit = mit->second.begin(); indexit!=mit->second.end(); indexit++) {
            indexs.push_back(*indexit);
        }
    }

    view->loadByIndex(indexs);
}


/*
 * press fileButton means reuniting the original file
 * open file messagebox
 */
void FileDialog::on_fileButton_clicked()
{
    QString saveFileName = QFileDialog::getSaveFileName(this, tr("Save As ... "), ".", tr("save to file"));
    if (!saveFileName.isEmpty()) {
        QFile file(saveFileName);
        if(file.open(QIODevice::WriteOnly)) //write text to file
        {
            QDataStream out(&file);
            QString name = model->data(model->index(targetFileIndex.row(), 0)).toString() + tr(":") + model->data(model->index(targetFileIndex.row(), 1)).toString();
            std::map<QString, std::vector<int> >::iterator mit = files.find(name);
            for (std::vector<int>::iterator indexit = mit->second.begin(); indexit!=mit->second.end(); indexit++) {
                //strugglling enough... don't use out<<
                out.writeRawData(view->packets.at(*indexit).protoInfo.strSendInfo.data(), view->packets.at(*indexit).protoInfo.strSendInfo.size());
            }
            file.close();
        }
    }
}



void FileDialog::on_fileTypeBox_activated(const QString &fileType)
{
    if (fileType==QObject::tr("all")) {
        displayFile();
        return;
    }
    choice.clear();
    for (std::map<QString, std::vector<int> >::iterator it = files.begin(); it != files.end(); it++) {
        if (fileType.indexOf(it->first.right(it->first.size() - it->first.indexOf(":") - 1))>=0) {
            choice.push_back(it->first);
        }
    }
    rebuildByType();
}

void FileDialog::rebuildByType()
{
    rebuild();
    QStandardItem *item;
    int index=0;
    for (std::vector<QString>::iterator it = choice.begin(); it!=choice.end(); it++) {
        std::map<QString, std::vector<int> >::iterator mit = files.find(*it);
        if (mit == files.end()) continue;
        item = new QStandardItem(mit->first.left(mit->first.indexOf(":")));
        model->setItem(index, 0, item);
        item = new QStandardItem(mit->first.right(mit->first.size() - mit->first.indexOf(":") - 1));
        model->setItem(index, 1, item);
        item = new QStandardItem(tr("unknown"));
        model->setItem(index, 2, item);
        item = new QStandardItem(QString::number(mit->second.size(), 10));
        model->setItem(index, 3, item);
        index++;
    }
}
