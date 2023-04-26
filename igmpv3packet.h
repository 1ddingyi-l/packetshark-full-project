#ifndef IGMPV3PACKET_H
#define IGMPV3PACKET_H

#include "pktf.h"
#include "packet.h"

class Igmpv3Packet : public Packet {
public:
    Igmpv3Packet(Packet *, quint16);

    quint8          getType();
    quint8          getMaxRespTime();
    quint16         getChecksum();
    QString         getGroupAddr();
    quint8          getResv();
    quint8          getS();
    quint8          getQRV();
    quint8          getQQI();           // get qqi by qqic
    quint16         getNumberOfSource();
    bool            check();

private:
    quint8          type;
    quint8          maxresptime;
    quint16         checksum;
    quint8          *groupaddr;
    quint8          resv;               // reserved field
    quint8          s;                  // s flag
    quint8          qrv;                // querier's robustness variable
    quint8          qqic;               // querier's query interval code
    quint16         numberOfSource;
    quint8          *sourceAddr[4];
};

#endif // IGMPV3PACKET_H
