TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap
LIBS += -lpthread

SOURCES += \
        dot11.cpp \
        hip.cpp \
        main.cpp \
        radiotap.cpp

HEADERS += \
    dot11.h \
    hip.h \
    include.h \
    mac.h \
    radiotap.h
