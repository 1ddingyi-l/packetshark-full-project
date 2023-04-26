#ifndef PACKETCAPTOR_H
#define PACKETCAPTOR_H

#include <QDebug>

#include <QThread>
#include <QVector>
#include <filesystem>
#include "packet.h"

namespace fs = std::filesystem;

class PacketCaptor : public QThread {
    Q_OBJECT

public:
    PacketCaptor();
    ~PacketCaptor();
    void                    clearPackets();
    void                    clearDevices();
    bool                    dumpPackets(QString);
    void                    deleteDefaultDumpFile();
    bool                    readPackets(QString);
    bool                    getState() const;
    void                    stop();
    void                    setDevice(pcap_if_t *);
    bool                    reloadDevices();
    bool                    movePacketsFileTo(QString);
    bool                    getArePacketsSaved() const;
    void                    setPromisc(int);
    bool                    getPromisc() const;
    void                    setHook();
    void                    clearHook();
    QString                 getCurDeviceName() const;
    QString                 getCurDeviceDescription() const;
    bool                    getIsEmpty() const;
    void                    setFilterRule(QString);

    QVector<pcap_if_t *>    devices;
    QVector<Packet *>       packets;

protected:
    virtual void run() override;

private:
    QString                 defaultFilePath = "packetDump.pcap";
    pcap_if_t *             devs            = static_cast<pcap_if_t *>(nullptr);
    pcap_if_t *             curdev          = static_cast<pcap_if_t *>(nullptr);
    pcap_t *                curdevP         = static_cast<pcap_t *>(nullptr);
    pcap_dumper *           dump            = static_cast<pcap_dumper *>(nullptr);
    char                    errBuf[PCAP_ERRBUF_SIZE];
    char                    tErrBuf[PCAP_ERRBUF_SIZE];
    bool                    isRunning       = false;
    qint16                  snaplen         = static_cast<qint16>(65535);
    qint16                  timeout         = 1000;
    qint32                  openFlag        = PCAP_OPENFLAG_PROMISCUOUS;
    bool                    arePacketsSaved = true;
    quint32                 netmask         = 0xffffffff;
    bool                    hook            = false;
    QString                 filterRule;

signals:
    void                    packetArrival(Packet *);
    void                    packetFiltered();
    void                    readyForCapture();
    void                    captureDone();
    void                    compileError(QString);

};

#endif // PACKETCAPTOR_H
