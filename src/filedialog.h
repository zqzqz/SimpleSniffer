#ifndef FILEDIALOG_H
#define FILEDIALOG_H

#include <QDialog>
#include "ui_filedialog.h"
#include "multiview.h"

class FileDialog: public QDialog
{
    Q_OBJECT

public:
    explicit FileDialog(MultiView *v, QWidget *parent = 0);
    ~FileDialog();
    void filtrateFile();
    void prepare();
    void displayFile();
    std::vector<QString> choice;
    QModelIndex targetFileIndex;

private slots:

    void on_buttonBox_accepted();

    void on_fileView_clicked(const QModelIndex &index);

    void on_fileButton_clicked();

    void on_fileTypeBox_activated(int index);

    void on_fileTypeBox_activated(const QString &arg1);

private:
    Ui::FileDialog *ui;
    MultiView *view;
    QStandardItemModel *model;
    std::map< QString, std::vector<int> > files;
    void rebuild();
    void rebuildByType();
};


#endif // FILEDIALOG_H
