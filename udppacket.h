#ifndef UDPPACKET_H
#define UDPPACKET_H

#include "pktf.h"
#include "packet.h"

class UdpPacket : public Packet {
public:
    UdpPacket(Packet *, quint16);
    quint16         getSrcPort();
    quint16         getDstPort();
    quint16         getChecksum();
    quint32         getPktLen() override;

private:
    quint16         src;
    quint16         dst;
    quint16         checksum;
    quint32         pktlen;
};

#endif // UDPPACKET_H
