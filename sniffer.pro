#-------------------------------------------------
#
# Project created by QtCreator 2017-11-19T08:57:55
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = sniffer
TEMPLATE = app
LIBS += -lpcap
QMAKE_CXXFLAGS += -std=c++11

# The following define makes your compiler emit warnings if you use
# any feature of Qt which has been marked as deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0


SOURCES += \
        src/main.cpp \
        src/mainwindow.cpp \
    src/csniffer.cpp \
    src/sniffer.cpp \
    src/networkchoice.cpp \
    src/capturethread.cpp \
    src/filter.cpp \
    src/listview.cpp \
    src/multiview.cpp \
    src/filedialog.cpp \
    src/slideinfo.cpp

HEADERS += \
        src/mainwindow.h \
    src/csniffer.h \
    src/log.h \
    src/sniffer.h \
    src/type.h \
    src/networkchoice.h \
    src/capturethread.h \
    src/filter.h \
    src/listview.h \
    src/multiview.h \
    src/filedialog.h \
    src/slideinfo.h

FORMS += \
        ui/mainwindow.ui \
    ui/networkchoice.ui \
    ui/filedialog.ui

RESOURCES += sniffer.qrc \
    sniffer.qrc
