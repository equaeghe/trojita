QT += core network
CONFIG += qtestlib no_lflags_merge
DEFINES -= QT3_SUPPORT
DEPENDPATH += ../../src/
INCLUDEPATH += ../../src/ ../
TARGET = test_Imap_LowLevelParser
TEMPLATE = app
SOURCES += test_Imap_LowLevelParser.cpp
HEADERS += test_Imap_LowLevelParser.h \
    ../qtest_kde.h

LIBS += -L../../src/Imap/Parser -L../../src/Imap/Model -L../../src/Streams
LIBS += -lImapParser -lImapModel -lImapParser -lStreams

PRE_TARGETDEPS += ../../src/Imap/Parser/libImapParser.a \
    ../../src/Imap/Model/libImapModel.a \
    ../../src/Streams/libStreams.a
