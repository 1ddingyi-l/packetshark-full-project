#ifndef TCPPACKET_H
#define TCPPACKET_H

#include "pktf.h"
#include "packet.h"

class TcpPacket : public Packet {
public:
    TcpPacket(Packet *, quint16);
    quint16         getSrcPort();
    quint16         getDstPort();
    quint32         getSeqN();
    quint32         getAckN();
    quint8          gethdrlen();
    quint16         getFlags();
    quint16         getWinSize();
    quint16         getChecksum();
    quint16         getUrgptr();
    quint32         getPktLen() override;

private:
    quint16         src;
    quint16         dst;
    quint32         seqN;
    quint32         ackN;
    quint8          hdrlen;
    quint16         flags;          // fin, syn, rst, psh, ack, urg, ece, cwr
    quint16         winsize;
    quint16         checksum;
    quint16         urgptr;
    quint32         pktlen;
};

#endif // TCPPACKET_H
