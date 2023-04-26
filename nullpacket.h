#ifndef NULLPACKET_H
#define NULLPACKET_H

#include "pktf.h"
#include "packet.h"

class NullPacket : public Packet {
public:
    NullPacket(Packet *);
    quint32             getFamily();
    quint32             getPktLen() override;

private:
    quint32             family;
    quint32             pktlen;
};

#endif // NULLPACKET_H
