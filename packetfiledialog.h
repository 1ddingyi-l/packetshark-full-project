#ifndef PACKETFILEDIALOG_H
#define PACKETFILEDIALOG_H

#include <QFileDialog>
#include <QString>

class PacketFileDialog : public QFileDialog {
public:
    PacketFileDialog();
    static QString                  getOpenPcapFileName();
    static QString                  getSavePcapFileName();
};

#endif // PACKETFILEDIALOG_H
