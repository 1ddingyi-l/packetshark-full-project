#ifndef IGMPPACKET_H
#define IGMPPACKET_H

#include "pktf.h"
#include "packet.h"

class IgmpPacket : Packet {
public:
    IgmpPacket(Packet *, quint16);
    quint8              getType();
    quint8              getMaxRespTime();
    quint16             getChecksum();
    QString             getGroupAddr();
    quint32             getPktLen() override;
    bool                check();

private:
    quint8              type;
    quint8              maxresptime;
    quint16             checksum;
    quint8              *groupaddr;
    quint32             pktlen;
};

#endif // IGMPPACKET_H
