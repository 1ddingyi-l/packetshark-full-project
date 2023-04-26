#ifndef IPV4PACKET_H
#define IPV4PACKET_H

#include "pktf.h"
#include "packet.h"

class IPv4Packet : public Packet {
public:
    IPv4Packet(Packet *, quint16);
    quint8          getVersion();
    quint8          getHeaderLen();
    quint8          getDiffServices();
    quint16         getTotalLen();
    quint16         getIden();
    quint16         getFlags();
    quint16         getFragmentOffset();
    quint8          getTtl();
    quint8          getProtocol();
    quint16         getChecksum();
    QString         getSrc();
    QString         getDst();
    quint32 *       getOptions();
    bool            hasOptions();
    quint32         getPktLen() override;

private:
    const quint8    defaultLen = 20;     // fixed bytes
    quint8          version;
    quint8          hdrlen;
    quint8          diffServices;
    quint16         totalLen;
    quint16         iden;
    quint16         flags;
    quint16         fragmentOffset;
    quint8          ttl;
    quint8          protocol;
    quint16         checksum;
    quint8          *src;
    quint8          *dst;
    quint32         *options = nullptr;
    quint32         pktlen;
};

#endif // IPV4PACKET_H
