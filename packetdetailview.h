#ifndef PACKETDETAILVIEW_H
#define PACKETDETAILVIEW_H

#include <QMainWindow>
#include <QShowEvent>
#include "packet.h"

#include "ethernetpacket.h"
#include "nullpacket.h"
#include "ipv4packet.h"
#include "ipv6packet.h"
#include "arppacket.h"
#include "icmppacket.h"
#include "igmppacket.h"
#include "igmpv3packet.h"
#include "tcppacket.h"
#include "udppacket.h"

namespace Ui {
class PacketDetailView;
}

class PacketDetailView : public QMainWindow {
    Q_OBJECT

public:
    explicit PacketDetailView(Packet *,
                              QWidget *parent = nullptr);
    ~PacketDetailView();

private:
    void                                showEvent(QShowEvent *) override;

    Ui::PacketDetailView *ui;
    Packet *                            pkt;
    struct timeval                      captureStartingTime;
    QFont                               detailedPacketViewFont{"Consolas", 12};
    QFont                               rawPacketViewFont{"Consolas", 12};
};

#endif // PACKETDETAILVIEW_H
