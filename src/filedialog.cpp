#include "filedialog.h"
#include <QFileDialog>

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
    for (std::vector< std::map<int, int> >::iterator it = view->fileFlow.begin(); it<view->fileFlow.end(); it++) {
        // find the smallest seq as start
        std::map<int, int>::iterator mit = it->end(); mit--;
        QString name;
        int seq = mit->first;
        int index = mit->second;
        SnifferData snifferData = view->packets.at(index);
        QByteArray payload = snifferData.protoInfo.strSendInfo;

        //analyse file type by common file headers
        if (payload.indexOf(QByteArray::fromHex("89504e47")) ==0) {
            name = QString::number(id, 10) + tr(":PNG"); //test a png file
        }
        else if (payload.indexOf(QByteArray::fromHex("d0cf11e0a1b11ae1")) ==0) {
            name = QString::number(id, 10) + tr(":doc"); //test a doc file
        }
        else {
            continue;
        }
        std::vector<int> indexs; indexs.push_back(index);


        while (true) {
            //calculate next seq
            _ip_header* iph = (_ip_header*) snifferData.protoInfo.pip;
            _tcp_header* tcph = (_tcp_header*) snifferData.protoInfo.ptcp;
            seq += (ntohs(iph->tlen) - ntohs(iph->ver_ihl & 0x0F)*4 - ntohs(tcph->thl)*4);
            //find next packet by seq
            mit = it->find(seq);
            if (mit == it->end()) break; //end
            else {
                index = mit->second;
                indexs.push_back(index);
            }
        }
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
    ui->fileView->setTextElideMode(Qt::ElideMiddle);
    ui->fileView->setEditTriggers(QAbstractItemView::NoEditTriggers);
}

void FileDialog::on_fileView_clicked(const QModelIndex &index)
{
    std::vector<QModelIndex>::iterator it = std::find(choice.begin(), choice.end(), index);
    if (it == choice.end()) {
        choice.push_back(index);
    }
    else {
        choice.erase(it);
    }
    targetFileIndex = index;
}

/*
 * press OK in fileDialog means displaying packets which transmit selected files
 *
 */
void FileDialog::on_buttonBox_accepted()
{
    std::vector<int> indexs;
    for (std::vector<QModelIndex>::iterator it = choice.begin(); it!=choice.end(); it++) {
        QString name = model->data(model->index(it->row(), 0)).toString() + tr(":") + model->data(model->index(it->row(), 1)).toString();
        std::map<QString, std::vector<int> >::iterator mit = files.find(name);
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
