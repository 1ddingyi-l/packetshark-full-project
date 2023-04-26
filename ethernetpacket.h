#ifndef ETHERNETPACKET_H
#define ETHERNETPACKET_H

#include "pktf.h"
#include "packet.h"

class EthernetPacket : public Packet {
public:
    enum protocol : quint16 {
        ipv4    = 0x0800,
        ipv6    = 0x86dd,
        arp     = 0x0806,
        unknown = 0xffff,
    };

    EthernetPacket(Packet *);
    QString         getSrc();
    QString         getDst();
    enum protocol   getUpperType();
    quint32         getPktLen() override;     // return caplen

private:
    quint8          *src;
    quint8          *dst;
    quint16         type;
};

#endif // ETHERNETPACKET_H
