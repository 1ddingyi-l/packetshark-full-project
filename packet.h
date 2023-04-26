#ifndef PACKET_H
#define PACKET_H

#include <QColor>
#include <QObject>
#include <pcap/pcap.h>

class Packet {
public:
    enum marks : qint8 {
        etherpkt,
        ipv4pkt,
        ipv6pkt,
        arppkt,
        icmppkt,
        igmppkt,
        tcppkt,
        udppkt,
        dnspkt,
        httppkt,
        httpspkt
    };

    Packet(quint64,                             // number
           struct pcap_pkthdr *,                // header
           qint32,                              // link type
           const u_char *,                      // raw packet
           quint16,                             // offset
           QString,                             // from device name
           QString);                            // from device description
    Packet(Packet *,
           quint16 = 0);
    virtual ~Packet();

    quint64                     getNumber();
    quint32                     getLen();
    quint32                     getCapLen();
    virtual quint32             getPktLen();
    qint32                      getLinkType();
    quint16                     getOffset();
    struct timeval              getTimeval();
    virtual QColor              getColor();
    u_char                      getByte(quint32);
    const struct pcap_pkthdr    getHeader();
    void                        setMark(qint32);
    QString                     getProtocolStack();
    void                        setProtocolStack(QString);
    QString                     getFromDeviceName();
    QString                     getFromDeviceDescription();

protected:
    const u_char *              rawpkt;

private:
    struct pcap_pkthdr          pkthdr;
    quint64                     number;         // packet number
    quint32                     len;            // packet length on line
    quint32                     caplen;         // packet length captured
    qint32                      linktype;       // link type
    quint16                     offset;         // packet offset from the begining
    struct timeval              tv;             // time stamp
    qint32                      mark = 0;
    QString                     protocolStack;
    QString                     fromDeviceName;
    QString                     fromDeviceDescription;


};

#endif // PACKET_H
