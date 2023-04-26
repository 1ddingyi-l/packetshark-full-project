#ifndef ARPPACKET_H
#define ARPPACKET_H

#include "pktf.h"
#include "packet.h"

class ARPPacket : public Packet {
public:
    ARPPacket(Packet *, quint16);
    quint16                 getType();
    quint16                 getProtocol();
    quint8                  getHAddrLen();
    quint8                  getPAddrLen();
    quint16                 getOpcode();
    QString                 getHSrc();
    QString                 getPSrc();
    QString                 getHDst();
    QString                 getPDst();
    quint32                 getPktLen() override;

private:
    quint16                 type;
    quint16                 protocol;
    quint8                  haddrlen;
    quint8                  paddrlen;
    quint16                 opcode;
    quint8                  *hSrc;
    quint8                  *pSrc;
    quint8                  *hDst;
    quint8                  *pDst;
    quint32                 pktlen;
};

#endif // ARPPACKET_H
