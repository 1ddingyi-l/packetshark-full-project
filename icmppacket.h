#ifndef ICMPPACKET_H
#define ICMPPACKET_H

#include "pktf.h"
#include "packet.h"

class IcmpPacket : public Packet {
public:
    IcmpPacket(Packet *, quint16);
    quint8              getType();
    quint8              getCode();
    quint16             getChecksum();
    quint16             getIden();
    quint16             getSeq();
    quint32             getPktLen() override;
    const u_char *      getData();

private:
    quint8              type;
    quint8              code;
    quint16             checksum;
    quint16             iden;
    quint16             seq;
    quint32             pktlen;
    const u_char        *data;
};

#endif // ICMPPACKET_H
