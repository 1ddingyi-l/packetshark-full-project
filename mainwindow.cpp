#include "mainwindow.h"
#include "./ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
    , srcModel(new QStandardItemModel())
    , model(new PacketFilterProxyModel)
    , group(this)
    , info(new QLabel()) {
    ui->setupUi(this);

    // initialize information of this window
    setWindowTitle(title);
    setWindowIcon(QIcon(":/icon.png"));

    // set basic information for table widget
    model->setSourceModel(srcModel);
    ui->packetListView->setModel(model);
    ui->packetListView->setSortingEnabled(true);
    // set action group
    group.addAction(ui->actionPackets_captured_filter);
    group.addAction(ui->actionFlow_traffic_filter);
    group.setExclusive(true);

    // connect slots to signals
    connect(ui->actionOpen, SIGNAL(triggered()), this, SLOT(openClicked()));
    connect(ui->actionSave, SIGNAL(triggered()), this, SLOT(saveClicked()));
    connect(ui->actionAbout_me, SIGNAL(triggered()), this, SLOT(aboutMeClicked()));
    connect(ui->actionAbout_my_school, SIGNAL(triggered()), this, SLOT(aboutMySchoolClicked()));
    connect(ui->actionFilter_rules, SIGNAL(triggered()), this, SLOT(openFilterRuleWebsite()));
    connect(ui->actionSave_as, SIGNAL(triggered()), this, SLOT(saveAs()));
    connect(ui->btnTrigger, SIGNAL(clicked()), this, SLOT(triggerAction()));
    connect(ui->deviceListView, SIGNAL(currentIndexChanged(int)), this, SLOT(setDevice(int)));
    connect(ui->btnReload, SIGNAL(clicked()), this, SLOT(reloadDeviceList()));
    connect(ui->filter, SIGNAL(returnPressed()), this, SLOT(filterPackets()));
    connect(&group, SIGNAL(triggered(QAction*)), this, SLOT(setCurrentFilter(QAction*)));
    connect(ui->packetListView->selectionModel(),
            SIGNAL(selectionChanged(QItemSelection,QItemSelection)),
            this,
            SLOT(showPacketDetail(QItemSelection,QItemSelection)));
    connect(ui->packetListView,
            SIGNAL(doubleClicked(QModelIndex)),
            this,
            SLOT(showPacketDetailWindow(QModelIndex)));
    connect(ui->promisc, SIGNAL(stateChanged(int)), this, SLOT(checkChanged(int)));
    connect(&captor, SIGNAL(packetArrival(Packet*)), this, SLOT(parsePacket(Packet*)));
    connect(&captor, SIGNAL(compileError(QString)), this, SLOT(errorHandler(QString)));
    connect(&captor, SIGNAL(readyForCapture()), this, SLOT(ready()));
    connect(&captor, SIGNAL(captureDone()), this, SLOT(done()));

    statusBar()->addWidget(info);
}

MainWindow::~MainWindow() {
    delete model;
    delete ui;
}

void MainWindow::triggerAction() {
    if (!captor.getState()) {                                           // start capture
        if (captor.packets.size() != 0 && !captor.getArePacketsSaved()) {
            enum confirmState state = confirm();
            switch (state) {
            case dumpPackets: {                                         // save packets and start a new packet capture
                PacketFileDialog dialog;
                QString filePath = dialog.getSavePcapFileName();
                if (filePath == "")
                    return;                                             // cancelling file path selection equals to cancel this oepration
                if (!captor.dumpPackets(filePath)) {                    // the file being replaced has beed opened!
                    QMessageBox::critical(nullptr, "Error", "The file being replaced has been opened!\n"
                                                            "Please close that reference before this operation.");
                    return;
                }
                break;
            }
            case cancel: {                                              // cancel this operation
                return;
            }
            default: {                                                  // drop packets directly and start a new packet capture
                break;
            }
            }
        }
        captor.start();
        return;
    }
    captor.stop();
}

void MainWindow::reloadDeviceList() {
    if (captor.reloadDevices() && captor.devices.size() != 0) {
        ui->deviceListView->clear();
        for (int i = 0; i < captor.devices.size(); i++) {
            ui->deviceListView->addItem(captor.devices[i]->description);
            ui->deviceListView->setItemData(i,
                                            Qt::AlignCenter,
                                            Qt::TextAlignmentRole);
        }
    }
}

void MainWindow::setDevice(int index) {
    if (index == -1)
        return;
    pcap_if_t *dev = captor.devices.at(index);
    captor.setDevice(dev);
    description = dev->description;
    updateStatusBar();
}

void MainWindow::parsePacket(Packet *pkt) {
    if (pkt->getNumber() == 1)
        captureStartingTime = pkt->getTimeval();                        // use that arrival time of the first packet as starting time

    qint32 linktype = pkt->getLinkType();
    quint64 number = pkt->getNumber();
    int row = number - 1;                                               // begin from index 0
    double f1 = pkt->getTimeval().tv_sec + (pkt->getTimeval().tv_usec / 1e6),
            f2 = captureStartingTime.tv_sec + (captureStartingTime.tv_usec / 1e6);
    quint32 caplen = pkt->getCapLen();
    QString arrtime = QString::number(f1 - f2, 'f');
    QList<QString> protocolStack;



    switch (linktype) {
    case DLT_EN10MB: {
        EthernetPacket epkt(pkt);
        protocolStack.append("eth");
        QString src = epkt.getSrc(),
                dst = epkt.getDst(),
                protocol = "Ethernet",
                info = "ieee 802.3 packet";
        quint16 utype = epkt.getUpperType();
        if (utype <= 0x05dc) {                                          // length
            protocol = "XID";
        } else
            switch (utype) {
            case EthernetPacket::ipv4: {
                IPv4Packet ipv4pkt(pkt, 14);
                protocolStack.append("ipv4");
                src = ipv4pkt.getSrc();
                dst = ipv4pkt.getDst();
                switch (ipv4pkt.getProtocol()) {                            // get ipv4 upper protocol
                case 0x01: {                                                // icmp packet
                    IcmpPacket icmppkt(pkt, 14 + ipv4pkt.getHeaderLen());
                    protocolStack.append("icmp");
                    protocol = "ICMPv4";
                    pkt->setMark(Packet::icmppkt);
                    switch (icmppkt.getType()) {
                    case 0x08: {                                            // echo request (used to ping)
                        info = "Echo (Ping) Request Id=0x" + QString::number(icmppkt.getIden(), 16) + ", Seq=" +
                                QString::number(icmppkt.getSeq()) + ", Ttl=" + QString::number(ipv4pkt.getTtl()) + " (Reply in " + QString::number(icmppkt.getNumber() + 1) +
                                ')';
                        break;
                    }
                    case 0x00: {                                            // echo reply (used to ping)
                        info = "Echo (Ping) Reply Id=0x" + QString::number(icmppkt.getIden(), 16) + ", Seq=" +
                                QString::number(icmppkt.getSeq()) + ", Ttl=" + QString::number(ipv4pkt.getTtl()) + " (Request in " + QString::number(icmppkt.getNumber() - 1) +
                                ')';
                        break;
                    }
                    default:
                        break;
                    }

                    break;
                }
                case 0x02: {                                                // igmp packet
                    IgmpPacket igmppkt(pkt, 14 + ipv4pkt.getHeaderLen());
                    protocolStack.append("igmp");
                    QString groupaddr = igmppkt.getGroupAddr();
                    protocol = "IGMPv2";
                    pkt->setMark(Packet::igmppkt);
                    switch (igmppkt.getType()) {
                    case 0x11: {                                            // membership query
                        if (groupaddr == "0.0.0.0")
                            info = "Membership Query, General";
                        else
                            info = "Membership Query, Specific for Group " + groupaddr;
                        break;
                    }
                    case 0x12: {                                            // igmpv1 membership report
                        protocol = "IGMPv1";
                        info = "Igmpv1 Membership Report Group" + groupaddr;
                        break;
                    }
                    case 0x16:                                              // igmpv2 membership report
                        info = "Membership Report Group " + groupaddr;
                        break;
                    case 0x17:                                              // leave group
                        info = "Leave Group " + groupaddr;
                        break;
                    case 0x22: {                                            // igmpv3 membership report
                        protocol = "IGMPv3";
                        info = "Igmpv3 Membership Report";
                        break;
                    }
                    }
                    break;
                }
                case 0x06: {                                                // tcp packet
                    TcpPacket tcppkt(pkt, 14 + ipv4pkt.getHeaderLen());
                    protocolStack.append("tcp");
                    if (tcppkt.getSrcPort() < 1024 || tcppkt.getDstPort() < 1024) {
                        // known port
                        if (tcppkt.getSrcPort() < 1024) {
                            switch (tcppkt.getSrcPort()) {
                            case 53:                                        // dns
                                protocolStack.append("dns");
                                protocol = "DNS";
                                pkt->setMark(Packet::dnspkt);
                                break;
                            case 80:                                        // http
                                protocol = "HTTP";
                                protocolStack.append("http");
                                pkt->setMark(Packet::httppkt);
                                break;
                            case 443:                                       // https
                                protocol = "HTTPs";
                                protocolStack.append("https");
                                pkt->setMark(Packet::httpspkt);
                                break;
                            }
                            break;
                        }
                        if (tcppkt.getDstPort() < 1024) {
                            switch (tcppkt.getDstPort()) {
                            case 53:                                        // dns
                                protocol = "DNS";
                                protocolStack.append("dns");
                                pkt->setMark(Packet::dnspkt);
                                break;
                            case 80:                                        // http
                                protocol = "HTTP";
                                protocolStack.append("http");
                                pkt->setMark(Packet::httppkt);
                                break;
                            case 443:                                       // https
                                protocol = "HTTPs";
                                protocolStack.append("https");
                                pkt->setMark(Packet::httpspkt);
                                break;
                            }
                            break;
                        }
                    } else {
                        protocol = "TCP";
                        pkt->setMark(Packet::tcppkt);
                        info = QString::number(tcppkt.getSrcPort()) + " -> " +
                                QString::number(tcppkt.getDstPort()) + ' ';
                        quint16 flags = tcppkt.getFlags();
                        for (int i = 0x001; i != 0x200; i <<= 1) {
                            if ((i & flags) != 0)
                                switch (i) {
                                case 0x001:
                                    info += "[FIN]";
                                    break;
                                case 0x002:
                                    info += "[SYN]";
                                    break;
                                case 0x004:
                                    info += "[RST]";
                                    break;
                                case 0x008:
                                    info += "[PSH]";
                                    break;
                                case 0x010:
                                    info += "[ACK]";
                                    break;
                                case 0x020:
                                    info += "[URG]";
                                    break;
                                case 0x040:
                                    info += "[ECN]";
                                    break;
                                case 0x080:
                                    info += "[CWR]";
                                    break;
                                case 0x100:
                                    info += "[NONCE]";
                                    break;
                                }
                        }
                        info += " Seq=" + QString::number(tcppkt.getSeqN()) + " Ack=" + QString::number(tcppkt.getAckN()) +
                                " Win=" + QString::number(tcppkt.getWinSize()) + " Len=" + QString::number(tcppkt.getPktLen());
                    }
                    break;
                }
                case 0x11: {                                                // udp packet
                    UdpPacket udppkt(pkt, 14 + ipv4pkt.getHeaderLen());
                    protocolStack.append("udp");
                    if (udppkt.getSrcPort() < 1024 || udppkt.getDstPort() < 1024) {
                        // known ports
                        if (udppkt.getSrcPort() < 1024) {
                            switch (udppkt.getSrcPort()) {
                            case 53:
                                protocolStack.append("dns");
                                protocol = "DNS";
                                pkt->setMark(Packet::dnspkt);
                                break;
                            case 80:
                                protocolStack.append("http");
                                protocol = "HTTP";
                                pkt->setMark(Packet::httppkt);
                                break;
                            case 443:
                                protocolStack.append("https");
                                protocol = "HTTPs";
                                pkt->setMark(Packet::httpspkt);
                                break;
                            }
                            break;
                        }
                        if (udppkt.getDstPort() < 1024) {
                            switch (udppkt.getDstPort()) {
                            case 53:
                                protocolStack.append("dns");
                                protocol = "DNS";
                                pkt->setMark(Packet::dnspkt);
                                break;
                            case 80:
                                protocolStack.append("http");
                                protocol = "HTTP";
                                pkt->setMark(Packet::httppkt);
                                break;
                            case 443:
                                protocolStack.append("https");
                                protocol = "HTTPs";
                                pkt->setMark(Packet::httpspkt);
                                break;
                            }
                            break;
                        }
                    } else {
                        protocol = "UDP";
                        pkt->setMark(Packet::udppkt);
                        info = QString::number(udppkt.getSrcPort()) + " -> " +
                                QString::number(udppkt.getDstPort()) + " Len=" +
                                QString::number(udppkt.getPktLen());
                    }
                    break;
                }
                default: {                                                  // unimplemented or unknown packets
                    break;
                }
                }
                break;
            }
            case EthernetPacket::arp: {
                ARPPacket arppkt(pkt, 14);
                protocolStack.append("arp");
                src = arppkt.getPSrc();
                dst = arppkt.getPDst();
                protocol = "ARP";
                pkt->setMark(Packet::arppkt);
                if (arppkt.getOpcode() == 1)                                // request
                    info = "Who has " + arppkt.getPDst() + "? Tell " + arppkt.getPSrc();
                else if (arppkt.getOpcode() == 2)                           // reply
                    info = arppkt.getPSrc() + " is at " + arppkt.getHSrc();
                // else unknown info
                break;
            }
            case EthernetPacket::ipv6: {
                IPv6Packet ipv6pkt(pkt, 14);
                protocolStack.append("ipv6");
                src = ipv6pkt.getSrc();
                dst = ipv6pkt.getDst();
                switch (ipv6pkt.getNextHeader()) {
                case 0x06: {                                                // tcp
                    TcpPacket tcppkt(pkt, 14 + ipv6pkt.getPktLen() - ipv6pkt.getPayloadLen());
                    protocolStack.append("tcp");
                    if (tcppkt.getSrcPort() < 1024 || tcppkt.getDstPort() < 1024) {
                        // known ports
                        if (tcppkt.getSrcPort() < 1024) {
                            switch (tcppkt.getSrcPort()) {
                            case 64:                                        // dns
                                protocolStack.append("dns");
                                break;
                            case 80:                                        // http
                                protocolStack.append("http");
                                break;
                            case 443:                                       // https
                                protocolStack.append("https");
                                break;
                            }
                            break;
                        }
                        if (tcppkt.getDstPort() < 1024) {
                            switch (tcppkt.getDstPort()) {
                            case 80:                                        // http
                                protocolStack.append("http");
                                break;
                            case 443:                                       // https
                                protocolStack.append("https");
                                break;
                            case 64:                                        // dns
                                protocolStack.append("dns");
                                break;
                            }
                        }
                    } else {
                        protocol = "TCP";
                        pkt->setMark(Packet::tcppkt);
                        info = QString::number(tcppkt.getSrcPort()) + " -> " +
                                QString::number(tcppkt.getDstPort()) + ' ';
                        quint16 flags = tcppkt.getFlags();
                        for (int i = 0x001; i != 0x200; i <<= 1) {
                            if ((i & flags) != 0)
                                switch (i) {
                                case 0x001:
                                    info += "[FIN]";
                                    break;
                                case 0x002:
                                    info += "[SYN]";
                                    break;
                                case 0x004:
                                    info += "[RST]";
                                    break;
                                case 0x008:
                                    info += "[PSH]";
                                    break;
                                case 0x010:
                                    info += "[ACK]";
                                    break;
                                case 0x020:
                                    info += "[URG]";
                                    break;
                                case 0x040:
                                    info += "[ECN]";
                                    break;
                                case 0x080:
                                    info += "[CWR]";
                                    break;
                                case 0x100:
                                    info += "[NONCE]";
                                    break;
                                }
                        }
                        info += " Seq=" + QString::number(tcppkt.getSeqN()) + " Ack=" + QString::number(tcppkt.getAckN()) +
                                " Win=" + QString::number(tcppkt.getWinSize()) + " Len=" + QString::number(tcppkt.getPktLen());
                    }
                    break;
                }
                case 0x11: {                                                // udp
                    UdpPacket udppkt(pkt, 14 + ipv6pkt.getPktLen() - ipv6pkt.getPayloadLen());
                    protocolStack.append("udp");
                    if (udppkt.getSrcPort() < 1024 || udppkt.getDstPort() < 1024) {
                        // known ports
                        if (udppkt.getSrcPort() < 1024) {
                            switch (udppkt.getSrcPort()) {
                            case 64:                                        // dns
                                protocolStack.append("dns");
                                break;
                            case 80:                                        // http
                                protocolStack.append("http");
                                break;
                            case 443:                                       // https
                                protocolStack.append("https");
                                break;
                            }
                            break;
                        }
                        if (udppkt.getDstPort() < 1024) {
                            switch (udppkt.getDstPort()) {
                            case 80:                                        // http
                                protocolStack.append("http");
                                break;
                            case 443:                                       // https
                                protocolStack.append("https");
                                break;
                            case 64:                                        // dns
                                protocolStack.append("dns");
                                break;
                            }
                        }
                    } else {
                        protocol = "UDP";
                        pkt->setMark(Packet::udppkt);
                        info = QString::number(udppkt.getSrcPort()) + " -> " + QString::number(udppkt.getDstPort()) + " Len="
                                + QString::number(udppkt.getPktLen());
                    }
                    break;
                }
                case 0x3a: {                                                // icmpv6
                    IcmpPacket icmppkt(pkt, 14 + ipv6pkt.getPktLen() - ipv6pkt.getPayloadLen());
                    protocolStack.append("icmp");
                    protocol = "ICMPv4";
                    pkt->setMark(Packet::icmppkt);
                    switch (icmppkt.getType()) {
                    case 0x08: {                                            // echo request (used to ping)
                        info = "Echo (Ping) Request Id=0x" + QString::number(icmppkt.getIden(), 16) + ", Seq=" +
                                QString::number(icmppkt.getSeq()) + ", Ttl=" + QString::number(ipv6pkt.getHopLimit()) + " (Reply in " + QString::number(icmppkt.getNumber() + 1) +
                                ')';
                        break;
                    }
                    case 0x00: {                                            // echo reply (used to ping)
                        info = "Echo (Ping) Reply Id=0x" + QString::number(icmppkt.getIden(), 16) + ", Seq=" +
                                QString::number(icmppkt.getSeq()) + ", Ttl=" + QString::number(ipv6pkt.getHopLimit()) + " (Request in " + QString::number(icmppkt.getNumber() - 1) +
                                ')';
                        break;
                    }
                    default:
                        break;
                    }
                    break;
                }
                }
                break;
            }
            default: {
                break;
            }
            }


        if (!protocolStack.isEmpty()) {
            if (!protocolStack.contains("arp"))
                protocolStack.append("data");
            pkt->setProtocolStack(protocolStack.join(':'));
        } else
            pkt->setProtocolStack("no protocol stack");


        srcModel->setRowCount(row);                                     // set model row number
        QList<QStandardItem *> sls;
        sls.append(new QStandardItem(QString::number(number)));
        sls.append(new QStandardItem(arrtime));
        sls.append(new QStandardItem(src));
        sls.append(new QStandardItem(dst));
        sls.append(new QStandardItem(QString::number(caplen)));
        sls.append(new QStandardItem(protocol));
        sls.append(new QStandardItem(info));
        srcModel->insertRow(row, sls);
        // set single item style
        for (int i = 0; i < sls.size(); i++) {
            QStandardItem *cell = sls[i];
            if (i < 5)
                cell->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
            else                                                        // protocol cell, info cell
                cell->setTextAlignment(Qt::AlignLeft | Qt::AlignVCenter);
            cell->setBackground(pkt->getColor());
        }
        break;
    }
    case DLT_NULL: {
        NullPacket nullpkt(pkt);
        protocolStack.append("null");
        quint32 family = nullpkt.getFamily();
        QString src = "unknown",
                dst = "unknown",
                protocol = "unknown",
                info = "unknown";
        switch (family) {
        case 0x02000000: {                                              // ipv4
            IPv4Packet ipv4pkt(pkt, 4);
            protocolStack.append("ipv4");
            src = ipv4pkt.getSrc();
            dst = ipv4pkt.getDst();
            switch (ipv4pkt.getProtocol()) {                            // get ipv4 upper protocol
            case 0x01: {                                                // icmp packet
                IcmpPacket icmppkt(pkt, 4 + ipv4pkt.getHeaderLen());
                protocolStack.append("icmp");
                protocol = "ICMPv4";
                pkt->setMark(Packet::icmppkt);
                switch (icmppkt.getType()) {
                case 0x08: {                                            // echo request (used to ping)
                    info = "Echo (Ping) Request Id=0x" + QString::number(icmppkt.getIden(), 16) + ", Seq=" +
                            QString::number(icmppkt.getSeq()) + ", Ttl=" + QString::number(ipv4pkt.getTtl()) + " (Reply in " + QString::number(icmppkt.getNumber() + 1) +
                            ')';
                    break;
                }
                case 0x00: {                                            // echo reply (used to ping)
                    info = "Echo (Ping) Reply Id=0x" + QString::number(icmppkt.getIden(), 16) + ", Seq=" +
                            QString::number(icmppkt.getSeq()) + ", Ttl=" + QString::number(ipv4pkt.getTtl()) + " (Request in " + QString::number(icmppkt.getNumber() - 1) +
                            ')';
                    break;
                }
                default:
                    break;
                }

                break;
            }
            case 0x02: {                                                // igmp packet
                IgmpPacket igmppkt(pkt, 4 + ipv4pkt.getHeaderLen());
                protocolStack.append("igmp");
                QString groupaddr = igmppkt.getGroupAddr();
                protocol = "IGMPv2";
                pkt->setMark(Packet::igmppkt);
                switch (igmppkt.getType()) {
                case 0x11: {                                            // membership query
                    if (groupaddr == "0.0.0.0")
                        info = "Membership Query, General";
                    else
                        info = "Membership Query, Specific for Group " + groupaddr;
                    break;
                }
                case 0x12: {                                            // igmpv1 membership report
                    protocol = "IGMPv1";
                    info = "Igmpv1 Membership Report Group" + groupaddr;
                    break;
                }
                case 0x16:                                              // igmpv2 membership report
                    info = "Membership Report Group " + groupaddr;
                    break;
                case 0x17:                                              // leave group
                    info = "Leave Group " + groupaddr;
                    break;
                case 0x22: {                                            // igmpv3 membership report
                    protocol = "IGMPv3";
                    info = "Igmpv3 Membership Report";
                    break;
                }
                }
                break;
            }
            case 0x06: {                                                // tcp packet
                TcpPacket tcppkt(pkt, 4 + ipv4pkt.getHeaderLen());
                protocolStack.append("tcp");
                if (tcppkt.getSrcPort() < 1024 || tcppkt.getDstPort() < 1024) {
                    // known port
                    if (tcppkt.getSrcPort() < 1024) {
                        switch (tcppkt.getSrcPort()) {
                        case 53:                                        // dns
                            protocol = "DNS";
                            protocolStack.append("dns");
                            pkt->setMark(Packet::dnspkt);
                            break;
                        case 80:                                        // http
                            protocol = "HTTP";
                            protocolStack.append("http");
                            pkt->setMark(Packet::httppkt);
                            break;
                        case 443:                                       // https
                            protocol = "HTTPs";
                            protocolStack.append("https");
                            pkt->setMark(Packet::httpspkt);
                            break;
                        }
                        break;
                    }
                    if (tcppkt.getDstPort() < 1024) {
                        switch (tcppkt.getDstPort()) {
                        case 53:                                        // dns
                            protocol = "DNS";
                            protocolStack.append("dns");
                            pkt->setMark(Packet::dnspkt);
                            break;
                        case 80:                                        // http
                            protocol = "HTTP";
                            protocolStack.append("http");
                            pkt->setMark(Packet::httppkt);
                            break;
                        case 443:                                       // https
                            protocol = "HTTPs";
                            protocolStack.append("https");
                            pkt->setMark(Packet::httpspkt);
                            break;
                        }
                        break;
                    }
                } else {
                    protocol = "TCP";
                    pkt->setMark(Packet::tcppkt);
                    info = QString::number(tcppkt.getSrcPort()) + " -> " +
                            QString::number(tcppkt.getDstPort()) + ' ';
                    quint16 flags = tcppkt.getFlags();
                    for (int i = 0x001; i != 0x200; i <<= 1) {
                        if ((i & flags) != 0)
                            switch (i) {
                            case 0x001:
                                info += "[FIN]";
                                break;
                            case 0x002:
                                info += "[SYN]";
                                break;
                            case 0x004:
                                info += "[RST]";
                                break;
                            case 0x008:
                                info += "[PSH]";
                                break;
                            case 0x010:
                                info += "[ACK]";
                                break;
                            case 0x020:
                                info += "[URG]";
                                break;
                            case 0x040:
                                info += "[ECN]";
                                break;
                            case 0x080:
                                info += "[CWR]";
                                break;
                            case 0x100:
                                info += "[NONCE]";
                                break;
                            }
                    }
                    info += " Seq=" + QString::number(tcppkt.getSeqN()) + " Ack=" + QString::number(tcppkt.getAckN()) +
                            " Win=" + QString::number(tcppkt.getWinSize()) + " Len=" + QString::number(tcppkt.getPktLen());
                }
                break;
            }
            case 0x11: {                                                // udp packet
                UdpPacket udppkt(pkt, 4 + ipv4pkt.getHeaderLen());
                protocolStack.append("udp");
                if (udppkt.getSrcPort() < 1024 || udppkt.getDstPort() < 1024) {
                    // known ports
                    if (udppkt.getSrcPort() < 1024) {
                        switch (udppkt.getSrcPort()) {
                        case 53:
                            protocol = "DNS";
                            protocolStack.append("dns");
                            pkt->setMark(Packet::dnspkt);
                            break;
                        case 80:
                            protocol = "HTTP";
                            protocolStack.append("http");
                            pkt->setMark(Packet::httppkt);
                            break;
                        case 443:
                            protocol = "HTTPs";
                            protocolStack.append("https");
                            pkt->setMark(Packet::httpspkt);
                            break;
                        }
                        break;
                    }
                    if (udppkt.getDstPort() < 1024) {
                        switch (udppkt.getDstPort()) {
                        case 53:
                            protocol = "DNS";
                            protocolStack.append("dns");
                            pkt->setMark(Packet::dnspkt);
                            break;
                        case 80:
                            protocol = "HTTP";
                            protocolStack.append("http");
                            pkt->setMark(Packet::httppkt);
                            break;
                        case 443:
                            protocol = "HTTPs";
                            protocolStack.append("https");
                            pkt->setMark(Packet::httpspkt);
                            break;
                        }
                        break;
                    }
                } else {
                    protocol = "UDP";
                    pkt->setMark(Packet::udppkt);
                    info = QString::number(udppkt.getSrcPort()) + " -> " +
                            QString::number(udppkt.getDstPort()) + " Len=" +
                            QString::number(udppkt.getPktLen());
                }
                break;
            }
            default: {                                                  // unimplemented or unknown packets
                break;
            }
            }
            break;
        }
#ifdef DEBUG
        default:
            qDebug() << family;
#endif
        }
        if (!protocolStack.isEmpty()) {
            if (!protocolStack.contains("arp"))
                protocolStack.append("data");
            pkt->setProtocolStack(protocolStack.join(':'));
        } else
            pkt->setProtocolStack("no protocol stack");


        srcModel->setRowCount(row);
        QList<QStandardItem *> sls;
        sls.append(new QStandardItem(QString::number(number)));
        sls.append(new QStandardItem(arrtime));
        sls.append(new QStandardItem(src));
        sls.append(new QStandardItem(dst));
        sls.append(new QStandardItem(QString::number(caplen)));
        sls.append(new QStandardItem(protocol));
        sls.append(new QStandardItem(info));
        srcModel->insertRow(row, sls);
        // set single item style
        for (int i = 0; i < sls.size(); i++) {
            QStandardItem *cell = sls[i];
            if (i < 5)
                cell->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
            else                                                        // protocol cell, info cell
                cell->setTextAlignment(Qt::AlignLeft | Qt::AlignVCenter);
            cell->setBackground(pkt->getColor());
        }
        break;
    }
    default: {
        qDebug() << "Haven't yet implemented it!";
        break;
    }
    }
}

void MainWindow::showPacketDetailWindow(const QModelIndex &index) {
    QModelIndex mappedIndex = model->mapToSource(index);
    int row = mappedIndex.row();
    if (row == -1 || row >= captor.packets.size())                      // invalid operation
        return;
    Packet *pkt = captor.packets[row];
    PacketDetailView *pdv = new PacketDetailView(pkt);
    pdv->setWindowTitle("Packetshark [Frame " + QString::number(pkt->getNumber()) + "] " + captor.getCurDeviceDescription());
    pdv->show();
    openedWindows.append(pdv);
}

void MainWindow::showPacketDetail(const QItemSelection &selected,
                                  const QItemSelection &deselected) {
    int currentRow, previousRow;
    if (selected.size() == 0)
        return;
    if (deselected.size() == 0) {  // the first selection
        currentRow = selected.indexes()[0].row();
        previousRow = -1;
    } else {
        currentRow = selected.indexes()[0].row();
        previousRow = deselected.indexes()[0].row();
    }
    if (currentRow == -1 || currentRow == previousRow || captor.packets.size() == 0)
        return;                                                         // invalid operation
    ui->detailedPacketView->clear();                                    // clear old data item
    ui->rawPacketView->clear();
    QModelIndex index = model->mapToSource(selected.indexes()[0]);
    Packet *pkt = captor.packets.at(index.row());                        // get that packet
    QVector<QTreeWidgetItem *> items;
    // show infomation by tree widget
    quint32 linktype = pkt->getLinkType();
    switch (linktype) {
    case DLT_EN10MB: {
        EthernetPacket epkt(pkt);
        QString src = epkt.getSrc();
        QString dst = epkt.getDst();
        quint16 type = epkt.getUpperType();
        QTreeWidgetItem *linklayer = new QTreeWidgetItem(QStringList() << "Ethernet II, Src: " + src + ", Dst: " + dst);
        linklayer->addChild(new QTreeWidgetItem(QStringList() << "Destination: " + dst));
        linklayer->addChild(new QTreeWidgetItem(QStringList() << "Source: " + src));
        linklayer->addChild(new QTreeWidgetItem(QStringList() << "Type: 0x" + QString::number(type, 16)));
        items.append(linklayer);
        switch (type) {
        case 0x0800: {                                                  // ipv4
            IPv4Packet ipv4pkt(pkt, 14);
            quint8 version = ipv4pkt.getVersion();
            quint8 hdrlen = ipv4pkt.getHeaderLen();
            quint8 diffSerives = ipv4pkt.getDiffServices();
            quint16 totalLen = ipv4pkt.getTotalLen();
            quint16 iden = ipv4pkt.getIden();
            quint16 flags = ipv4pkt.getFlags();
            quint16 offset = ipv4pkt.getFragmentOffset();
            quint8 ttl = ipv4pkt.getTtl();
            quint8 protocol = ipv4pkt.getProtocol();
            quint16 checksum = ipv4pkt.getChecksum();
            QString src = ipv4pkt.getSrc();
            QString dst = ipv4pkt.getDst();
            QTreeWidgetItem *networklayer = new QTreeWidgetItem(QStringList() << "Internet Protocol Version 4, Src: " + src + ", Dst: " + dst);
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Version: " + QString::number(version)));
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Header Length: " + QString::number(hdrlen)));
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Differentiated Services Field: 0x" + QString::number(diffSerives, 16)));
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Total Length: " + QString::number(totalLen)));
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Identification: 0x" + QString::number(iden, 16)));
            QTreeWidgetItem *flagswidget = new QTreeWidgetItem(QStringList() << "Flags: 0x" + QString::number(flags, 16));
            for (quint16 i = 0x8000; i != 0x1000; i >>= 1) {
                if ((i & flags) != 0)
                    switch (i) {
                    case 0x8000:                                        // reserved bit
                        flagswidget->addChild(new QTreeWidgetItem(QStringList() << "Reserved bit: 1"));
                        break;
                    case 0x4000:                                        // don't fragment
                        flagswidget->addChild(new QTreeWidgetItem(QStringList() << "Don't fragment: 1"));
                        break;
                    case 0x2000:                                        // more fragment
                        flagswidget->addChild(new QTreeWidgetItem(QStringList() << "More fragments: 1"));
                        break;
                    }
                else
                    switch (i) {
                    case 0x8000:                                        // reserved bit
                        flagswidget->addChild(new QTreeWidgetItem(QStringList() << "Reserved bit: 0"));
                        break;
                    case 0x4000:                                        // don't fragment
                        flagswidget->addChild(new QTreeWidgetItem(QStringList() << "Don't fragment: 0"));
                        break;
                    case 0x2000:                                        // more fragment
                        flagswidget->addChild(new QTreeWidgetItem(QStringList() << "More fragments: 0"));
                        break;
                    }
            }
            networklayer->addChild(flagswidget);
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Fragment Offset: " + QString::number(offset)));
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Time to Live: : " + QString::number(ttl)));
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Protocol: " + QString::number(protocol)));
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Header Checksum: 0x" + QString::number(checksum, 16)));
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Source Address: " + src));
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Destination Address: " + dst));
            items.append(networklayer);
            switch (protocol) {
            case 0x01: {                                                // icmp
                IcmpPacket icmppkt(pkt, 14 + ipv4pkt.getHeaderLen());
                quint8 type = icmppkt.getType();
                quint8 code = icmppkt.getCode();
                quint16 checksum = icmppkt.getChecksum();
                quint16 iden = icmppkt.getIden();
                quint16 seq = icmppkt.getSeq();
                QTreeWidgetItem *beforeNetworklayer = new QTreeWidgetItem(QStringList() << "Internet Control Message Protocol");
                beforeNetworklayer->addChild(new QTreeWidgetItem(QStringList() << "Type: " + QString::number(type)));
                beforeNetworklayer->addChild(new QTreeWidgetItem(QStringList() << "Code: " + QString::number(code)));
                beforeNetworklayer->addChild(new QTreeWidgetItem(QStringList() << "Checksum: 0x" + QString::number(checksum, 16)));
                beforeNetworklayer->addChild(new QTreeWidgetItem(QStringList() << "Identifier: " + QString::number(iden)));
                beforeNetworklayer->addChild(new QTreeWidgetItem(QStringList() << "Sequence: " + QString::number(seq)));
                items.append(beforeNetworklayer);
                break;
            }
            case 0x02: {                                                // igmp
                IgmpPacket igmppkt(pkt, 14 + ipv4pkt.getHeaderLen());
                quint8 type = igmppkt.getType();
                quint8 maxRespTime = igmppkt.getMaxRespTime();
                quint16 checksum = igmppkt.getChecksum();
                QString groupaddr = igmppkt.getGroupAddr();
                QTreeWidgetItem *beforeNetworklayer = new QTreeWidgetItem(QStringList() << "Internet Group Message Protocol");
                beforeNetworklayer->addChild(new QTreeWidgetItem(QStringList() << "Type: " + QString::number(type)));
                beforeNetworklayer->addChild(new QTreeWidgetItem(QStringList() << "Max Resp Time: 0x" + QString::number(maxRespTime, 16)));
                beforeNetworklayer->addChild(new QTreeWidgetItem(QStringList() << "Checksum: 0x" + QString::number(checksum, 16)));
                beforeNetworklayer->addChild(new QTreeWidgetItem(QStringList() << "Multicast Address: " + groupaddr));
                if (type == 0x22) {                                     // igmpv3
                    Igmpv3Packet igmpv3pkt(pkt, 14 + ipv4pkt.getHeaderLen());
                    quint8 reserved = igmpv3pkt.getResv();
                    quint8 s = igmpv3pkt.getS();
                    quint8 qrv = igmpv3pkt.getQRV();
                    quint8 qqi = igmpv3pkt.getQQI();
                    quint16 nos = igmpv3pkt.getNumberOfSource();
                    beforeNetworklayer->addChild(new QTreeWidgetItem(QStringList() << "Reserved: " + QString::number(reserved)));
                    beforeNetworklayer->addChild(new QTreeWidgetItem(QStringList() << "S Flag: " + QString::number(s)));
                    beforeNetworklayer->addChild(new QTreeWidgetItem(QStringList() << "Querier's Robustness Variable: " + QString::number(qrv)));
                    beforeNetworklayer->addChild(new QTreeWidgetItem(QStringList() << "Querier's Query Interval: " + QString::number(qqi)));
                    beforeNetworklayer->addChild(new QTreeWidgetItem(QStringList() << "Number of Sources: " + QString::number(nos)));
                }
                items.append(beforeNetworklayer);
                break;
            }
            case 0x06: {                                                // tcp
                TcpPacket tcppkt(pkt, 14 + ipv4pkt.getHeaderLen());
                quint16 srcPort = tcppkt.getSrcPort();
                quint16 dstPort = tcppkt.getDstPort();
                quint32 seqNumber = tcppkt.getSeqN();
                quint32 ackNumber = tcppkt.getAckN();
                quint8 hdrlen = tcppkt.gethdrlen();
                quint16 flags = tcppkt.getFlags();
                quint16 winsize = tcppkt.getWinSize();
                quint16 checksum = tcppkt.getChecksum();
                quint16 urgptr = tcppkt.getUrgptr();
                QTreeWidgetItem *transportlayer = new QTreeWidgetItem(QStringList() << "Transmission Control Protocol: Src Port: " + QString::number(srcPort) +
                                                                      ", Dst port: " + QString::number(dstPort));
                transportlayer->addChild(new QTreeWidgetItem(QStringList() << "Source Port: " + QString::number(srcPort)));
                transportlayer->addChild(new QTreeWidgetItem(QStringList() << "Destination Port: " + QString::number(dstPort)));
                transportlayer->addChild(new QTreeWidgetItem(QStringList() << "Sequence Number: " + QString::number(seqNumber)));
                transportlayer->addChild(new QTreeWidgetItem(QStringList() << "Acknowledge Number: " + QString::number(ackNumber)));
                transportlayer->addChild(new QTreeWidgetItem(QStringList() << "Header Length: " + QString::number(hdrlen)));
                QTreeWidgetItem *flagswidget = new QTreeWidgetItem(QStringList() << "Flags: 0x" + QString::number(flags, 16));
                for (int i = 0x001; i != 0x200; i <<= 1) {
                    if ((i & flags) != 0)
                        switch (i) {
                        case 0x001:                                     // fin
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "FIN: 1"));
                            break;
                        case 0x002:                                     // syn
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "SYN: 1"));
                            break;
                        case 0x004:                                     // rst
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "RST: 1"));
                            break;
                        case 0x008:                                     // psh
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "PSH: 1"));
                            break;
                        case 0x010:                                     // ack
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "ACK: 1"));
                            break;
                        case 0x020:                                     // urg
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "URG: 1"));
                            break;
                        case 0x040:                                     // ecn
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "ECN: 1"));
                            break;
                        case 0x080:                                     // cwr
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "CWR: 1"));
                            break;
                        case 0x100:                                     // nonce
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "NONCE: 1"));
                            break;
                        }
                    else
                        switch (i) {
                        case 0x001:                                     // fin
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "FIN: 0"));
                            break;
                        case 0x002:                                     // syn
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "SYN: 0"));
                            break;
                        case 0x004:                                     // rst
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "RST: 0"));
                            break;
                        case 0x008:                                     // psh
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "PSH: 0"));
                            break;
                        case 0x010:                                     // ack
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "ACK: 0"));
                            break;
                        case 0x020:                                     // urg
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "URG: 0"));
                            break;
                        case 0x040:                                     // ecn
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "ECN: 0"));
                            break;
                        case 0x080:                                     // cwr
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "CWR: 0"));
                            break;
                        case 0x100:                                     // nonce
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "NONCE: 0"));
                            break;
                        }
                }
                transportlayer->addChild(flagswidget);
                transportlayer->addChild(new QTreeWidgetItem(QStringList() << "Window Size: " + QString::number(winsize)));
                transportlayer->addChild(new QTreeWidgetItem(QStringList() << "Checksum: 0x" + QString::number(checksum, 16)));
                transportlayer->addChild(new QTreeWidgetItem(QStringList() << "Urgent Pointer: " + QString::number(urgptr)));
                items.append(transportlayer);
                break;
            }
            case 0x11: {                                                // udp
                UdpPacket udppkt(pkt, 14 + ipv4pkt.getHeaderLen());
                quint16 srcPort = udppkt.getSrcPort();
                quint16 dstPort = udppkt.getDstPort();
                quint16 checksum = udppkt.getChecksum();
                QTreeWidgetItem *transportlayer = new QTreeWidgetItem(QStringList() << "User Datagram Protocol, Src Port: " + QString::number(srcPort) + ", Dst Port: " + QString::number(dstPort));
                transportlayer->addChild(new QTreeWidgetItem(QStringList() << "Source Port: " + QString::number(srcPort)));
                transportlayer->addChild(new QTreeWidgetItem(QStringList() << "Destination Port: " + QString::number(dstPort)));
                transportlayer->addChild(new QTreeWidgetItem(QStringList() << "Checksum: 0x" + QString::number(checksum, 16)));
                items.append(transportlayer);
                break;
            }
            }
            break;
        }
        case 0x0806: {                                                  // arp
            ARPPacket arppkt(pkt, 14);
            quint16 htype = arppkt.getType();
            quint16 ptype = arppkt.getProtocol();
            quint8  hsize = arppkt.getHAddrLen();
            quint8  psize = arppkt.getPAddrLen();
            quint16 opcode = arppkt.getOpcode();
            QString hsrc = arppkt.getHSrc();
            QString psrc = arppkt.getPSrc();
            QString hdst = arppkt.getHDst();
            QString pdst = arppkt.getPDst();
            QTreeWidgetItem *networklayer = new QTreeWidgetItem(QStringList() << "Address Resolution Protocol");
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Hardware Type: " + QString::number(htype)));
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Protocol Type: 0x" + QString::number(ptype, 16)));
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Hardware Size: " + QString::number(hsize)));
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Protocol Size: " + QString::number(psize)));
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Opcode: " + QString::number(opcode)));
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Sender Hardware Address: " + hsrc));
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Sender Protocol Address: " + psrc));
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Target Hardware Address: " + hdst));
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Target Protocol Address: " + pdst));
            items.append(networklayer);
            break;
        }
        case 0x86dd:  {                                                 // ipv6
            IPv6Packet ipv6pkt(pkt, 14);
            quint8 version = ipv6pkt.getVersion();
            quint8 tf = ipv6pkt.getDiffServices();
            quint32 fl = ipv6pkt.getFlowLabel();
            quint16 payloadlen = ipv6pkt.getPayloadLen();
            quint8 nexthdr = ipv6pkt.getNextHeader();
            quint8 hoplimit = ipv6pkt.getHopLimit();
            QString src = ipv6pkt.getSrc();
            QString dst = ipv6pkt.getDst();
            QTreeWidgetItem *networklayer = new QTreeWidgetItem(QStringList() << "Internet Protocol Version 6, Src: " + src + ", Dst: " + dst);
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Version: " + QString::number(version)));
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Traffic Class: 0x" + QString::number(tf, 16)));
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Flow Label: 0x" + QString::number(fl, 16)));
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Payload Length: " + QString::number(payloadlen)));
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Next Header: " + QString::number(nexthdr)));
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Hop Limit: " + QString::number(hoplimit)));
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Source Address: " + src));
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Destination Address: " + dst));
            items.append(networklayer);
            switch (nexthdr) {
            case 0x06: {                                                // tcp
                TcpPacket tcppkt(pkt, 14 + ipv6pkt.getPktLen() - ipv6pkt.getPayloadLen());
                quint16 srcPort = tcppkt.getSrcPort();
                quint16 dstPort = tcppkt.getDstPort();
                quint32 seqNumber = tcppkt.getSeqN();
                quint32 ackNumber = tcppkt.getAckN();
                quint8 hdrlen = tcppkt.gethdrlen();
                quint16 flags = tcppkt.getFlags();
                quint16 winsize = tcppkt.getWinSize();
                quint16 checksum = tcppkt.getChecksum();
                quint16 urgptr = tcppkt.getUrgptr();
                QTreeWidgetItem *transportlayer = new QTreeWidgetItem(QStringList() << "Transmission Control Protocol: Src Port: " + QString::number(srcPort) +
                                                                      ", Dst Port: " + QString::number(dstPort));
                transportlayer->addChild(new QTreeWidgetItem(QStringList() << "Source Port: " + QString::number(srcPort)));
                transportlayer->addChild(new QTreeWidgetItem(QStringList() << "Destination Port: " + QString::number(dstPort)));
                transportlayer->addChild(new QTreeWidgetItem(QStringList() << "Sequence Number: " + QString::number(seqNumber)));
                transportlayer->addChild(new QTreeWidgetItem(QStringList() << "Acknowledge Number: " + QString::number(ackNumber)));
                transportlayer->addChild(new QTreeWidgetItem(QStringList() << "Header Length: " + QString::number(hdrlen)));
                QTreeWidgetItem *flagswidget = new QTreeWidgetItem(QStringList() << "Flags: 0x" + QString::number(flags, 16));
                for (int i = 0x001; i != 0x200; i <<= 1) {
                    if ((i & flags) != 0)
                        switch (i) {
                        case 0x001:                                     // fin
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "FIN: 1"));
                            break;
                        case 0x002:                                     // syn
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "SYN: 1"));
                            break;
                        case 0x004:                                     // rst
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "RST: 1"));
                            break;
                        case 0x008:                                     // psh
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "PSH: 1"));
                            break;
                        case 0x010:                                     // ack
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "ACK: 1"));
                            break;
                        case 0x020:                                     // urg
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "URG: 1"));
                            break;
                        case 0x040:                                     // ecn
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "ECN: 1"));
                            break;
                        case 0x080:                                     // cwr
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "CWR: 1"));
                            break;
                        case 0x100:                                     // nonce
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "NONCE: 1"));
                            break;
                        }
                    else
                        switch (i) {
                        case 0x001:                                     // fin
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "FIN: 0"));
                            break;
                        case 0x002:                                     // syn
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "SYN: 0"));
                            break;
                        case 0x004:                                     // rst
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "RST: 0"));
                            break;
                        case 0x008:                                     // psh
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "PSH: 0"));
                            break;
                        case 0x010:                                     // ack
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "ACK: 0"));
                            break;
                        case 0x020:                                     // urg
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "URG: 0"));
                            break;
                        case 0x040:                                     // ecn
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "ECN: 0"));
                            break;
                        case 0x080:                                     // cwr
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "CWR: 0"));
                            break;
                        case 0x100:                                     // nonce
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "NONCE: 0"));
                            break;
                        }
                }
                transportlayer->addChild(flagswidget);
                transportlayer->addChild(new QTreeWidgetItem(QStringList() << "Window Size: " + QString::number(winsize)));
                transportlayer->addChild(new QTreeWidgetItem(QStringList() << "Checksum: 0x" + QString::number(checksum, 16)));
                transportlayer->addChild(new QTreeWidgetItem(QStringList() << "Urgent Pointer: " + QString::number(urgptr)));
                items.append(transportlayer);
                break;
            }
            case 0x11: {                                                // udp
                UdpPacket udppkt(pkt, 14 + ipv6pkt.getPktLen() - ipv6pkt.getPayloadLen());
                quint16 srcPort = udppkt.getSrcPort();
                quint16 dstPort = udppkt.getDstPort();
                quint16 checksum = udppkt.getChecksum();
                QTreeWidgetItem *transportlayer = new QTreeWidgetItem(QStringList() << "User Datagram Protocol, Src Port: " + QString::number(srcPort) + ", Dst Port: " + QString::number(dstPort));
                transportlayer->addChild(new QTreeWidgetItem(QStringList() << "Source Port: " + QString::number(srcPort)));
                transportlayer->addChild(new QTreeWidgetItem(QStringList() << "Destination Port: " + QString::number(dstPort)));
                transportlayer->addChild(new QTreeWidgetItem(QStringList() << "Checksum: 0x" + QString::number(checksum, 16)));
                items.append(transportlayer);
                break;
            }
            case 0x3a: {                                                // icmp
                IcmpPacket icmppkt(pkt, 14 + ipv6pkt.getPktLen() - ipv6pkt.getPayloadLen());
                quint8 type = icmppkt.getType();
                quint8 code = icmppkt.getCode();
                quint16 checksum = icmppkt.getChecksum();
                quint16 iden = icmppkt.getIden();
                quint16 seq = icmppkt.getSeq();
                QTreeWidgetItem *beforeNetworklayer = new QTreeWidgetItem(QStringList() << "Internet Control Message Protocol");
                beforeNetworklayer->addChild(new QTreeWidgetItem(QStringList() << "Type: " + QString::number(type)));
                beforeNetworklayer->addChild(new QTreeWidgetItem(QStringList() << "Code: " + QString::number(code)));
                beforeNetworklayer->addChild(new QTreeWidgetItem(QStringList() << "Checksum: 0x" + QString::number(checksum, 16)));
                beforeNetworklayer->addChild(new QTreeWidgetItem(QStringList() << "Identifier: " + QString::number(iden)));
                beforeNetworklayer->addChild(new QTreeWidgetItem(QStringList() << "Sequence: " + QString::number(seq)));
                items.append(beforeNetworklayer);
                break;
            }
            }
            break;
        }
        }
        break;
    }
    case DLT_NULL: {
        NullPacket nullpkt(pkt);
        quint32 family = nullpkt.getFamily();
        QTreeWidgetItem *linklayer = new QTreeWidgetItem(QStringList() << "Null/Loopback");
        linklayer->addChild(new QTreeWidgetItem(QStringList() << "Family: 0x" + QString::number(family, 16)));
        items.append(linklayer);
        switch (family) {
        case 0x02000000: {                                              // ipv4
            IPv4Packet ipv4pkt(pkt, 4);
            quint8 version = ipv4pkt.getVersion();
            quint8 hdrlen = ipv4pkt.getHeaderLen();
            quint8 diffSerives = ipv4pkt.getDiffServices();
            quint16 totalLen = ipv4pkt.getTotalLen();
            quint16 iden = ipv4pkt.getIden();
            quint16 flags = ipv4pkt.getFlags();
            quint16 offset = ipv4pkt.getFragmentOffset();
            quint8 ttl = ipv4pkt.getTtl();
            quint8 protocol = ipv4pkt.getProtocol();
            quint16 checksum = ipv4pkt.getChecksum();
            QString src = ipv4pkt.getSrc();
            QString dst = ipv4pkt.getDst();
            QTreeWidgetItem *networklayer = new QTreeWidgetItem(QStringList() << "Internet Protocol Version 4, Src: " + src + ", Dst: " + dst);
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Version: " + QString::number(version)));
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Header Length: " + QString::number(hdrlen)));
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Differentiated Services Field: 0x" + QString::number(diffSerives, 16)));
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Total Length: " + QString::number(totalLen)));
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Identification: 0x" + QString::number(iden, 16)));
            QTreeWidgetItem *flagswidget = new QTreeWidgetItem(QStringList() << "Flags: 0x" + QString::number(flags, 16));
            for (quint16 i = 0x8000; i != 0x1000; i >>= 1) {
                if ((i & flags) != 0)
                    switch (i) {
                    case 0x8000:                                        // reserved bit
                        flagswidget->addChild(new QTreeWidgetItem(QStringList() << "Reserved bit: 1"));
                        break;
                    case 0x4000:                                        // don't fragment
                        flagswidget->addChild(new QTreeWidgetItem(QStringList() << "Don't fragment: 1"));
                        break;
                    case 0x2000:                                        // more fragment
                        flagswidget->addChild(new QTreeWidgetItem(QStringList() << "More fragments: 1"));
                        break;
                    }
                else
                    switch (i) {
                    case 0x8000:                                        // reserved bit
                        flagswidget->addChild(new QTreeWidgetItem(QStringList() << "Reserved bit: 0"));
                        break;
                    case 0x4000:                                        // don't fragment
                        flagswidget->addChild(new QTreeWidgetItem(QStringList() << "Don't fragment: 0"));
                        break;
                    case 0x2000:                                        // more fragment
                        flagswidget->addChild(new QTreeWidgetItem(QStringList() << "More fragments: 0"));
                        break;
                    }
            }
            networklayer->addChild(flagswidget);
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Fragment Offset: " + QString::number(offset)));
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Time to Live: : " + QString::number(ttl)));
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Protocol: " + QString::number(protocol)));
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Header Checksum: 0x" + QString::number(checksum, 16)));
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Source Address: " + src));
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Destination Address: " + dst));
            items.append(networklayer);
            switch (protocol) {
            case 0x01: {                                                // icmp
                IcmpPacket icmppkt(pkt, 4 + ipv4pkt.getHeaderLen());
                quint8 type = icmppkt.getType();
                quint8 code = icmppkt.getCode();
                quint16 checksum = icmppkt.getChecksum();
                quint16 iden = icmppkt.getIden();
                quint16 seq = icmppkt.getSeq();
                QTreeWidgetItem *beforeNetworklayer = new QTreeWidgetItem(QStringList() << "Internet Control Message Protocol");
                beforeNetworklayer->addChild(new QTreeWidgetItem(QStringList() << "Type: " + QString::number(type)));
                beforeNetworklayer->addChild(new QTreeWidgetItem(QStringList() << "Code: " + QString::number(code)));
                beforeNetworklayer->addChild(new QTreeWidgetItem(QStringList() << "Checksum: 0x" + QString::number(checksum, 16)));
                beforeNetworklayer->addChild(new QTreeWidgetItem(QStringList() << "Identifier: " + QString::number(iden)));
                beforeNetworklayer->addChild(new QTreeWidgetItem(QStringList() << "Sequence: " + QString::number(seq)));
                items.append(beforeNetworklayer);
                break;
            }
            case 0x02: {                                                // igmp
                IgmpPacket igmppkt(pkt, 4 + ipv4pkt.getHeaderLen());
                quint8 type = igmppkt.getType();
                quint8 maxRespTime = igmppkt.getMaxRespTime();
                quint16 checksum = igmppkt.getChecksum();
                QString groupaddr = igmppkt.getGroupAddr();
                QTreeWidgetItem *beforeNetworklayer = new QTreeWidgetItem(QStringList() << "Internet Group Message Protocol");
                beforeNetworklayer->addChild(new QTreeWidgetItem(QStringList() << "Type: " + QString::number(type)));
                beforeNetworklayer->addChild(new QTreeWidgetItem(QStringList() << "Max Resp Time: 0x" + QString::number(maxRespTime, 16)));
                beforeNetworklayer->addChild(new QTreeWidgetItem(QStringList() << "Checksum: 0x" + QString::number(checksum, 16)));
                beforeNetworklayer->addChild(new QTreeWidgetItem(QStringList() << "Multicast Address: " + groupaddr));
                if (type == 0x22) {                                     // igmpv3
                    Igmpv3Packet igmpv3pkt(pkt, 4 + ipv4pkt.getHeaderLen());
                    quint8 reserved = igmpv3pkt.getResv();
                    quint8 s = igmpv3pkt.getS();
                    quint8 qrv = igmpv3pkt.getQRV();
                    quint8 qqi = igmpv3pkt.getQQI();
                    quint16 nos = igmpv3pkt.getNumberOfSource();
                    beforeNetworklayer->addChild(new QTreeWidgetItem(QStringList() << "Reserved: " + QString::number(reserved)));
                    beforeNetworklayer->addChild(new QTreeWidgetItem(QStringList() << "S Flag: " + QString::number(s)));
                    beforeNetworklayer->addChild(new QTreeWidgetItem(QStringList() << "Querier's Robustness Variable: " + QString::number(qrv)));
                    beforeNetworklayer->addChild(new QTreeWidgetItem(QStringList() << "Querier's Query Interval: " + QString::number(qqi)));
                    beforeNetworklayer->addChild(new QTreeWidgetItem(QStringList() << "Number of Sources: " + QString::number(nos)));
                }
                items.append(beforeNetworklayer);
                break;
            }
            case 0x06: {                                                // tcp
                TcpPacket tcppkt(pkt, 4 + ipv4pkt.getHeaderLen());
                quint16 srcPort = tcppkt.getSrcPort();
                quint16 dstPort = tcppkt.getDstPort();
                quint32 seqNumber = tcppkt.getSeqN();
                quint32 ackNumber = tcppkt.getAckN();
                quint8 hdrlen = tcppkt.gethdrlen();
                quint16 flags = tcppkt.getFlags();
                quint16 winsize = tcppkt.getWinSize();
                quint16 checksum = tcppkt.getChecksum();
                quint16 urgptr = tcppkt.getUrgptr();
                QTreeWidgetItem *transportlayer = new QTreeWidgetItem(QStringList() << "Transmission Control Protocol: Src Port: " + QString::number(srcPort) +
                                                                      ", Dst port: " + QString::number(dstPort));
                transportlayer->addChild(new QTreeWidgetItem(QStringList() << "Source Port: " + QString::number(srcPort)));
                transportlayer->addChild(new QTreeWidgetItem(QStringList() << "Destination Port: " + QString::number(dstPort)));
                transportlayer->addChild(new QTreeWidgetItem(QStringList() << "Sequence Number: " + QString::number(seqNumber)));
                transportlayer->addChild(new QTreeWidgetItem(QStringList() << "Acknowledge Number: " + QString::number(ackNumber)));
                transportlayer->addChild(new QTreeWidgetItem(QStringList() << "Header Length: " + QString::number(hdrlen)));
                QTreeWidgetItem *flagswidget = new QTreeWidgetItem(QStringList() << "Flags: 0x" + QString::number(flags, 16));
                for (int i = 0x001; i != 0x200; i <<= 1) {
                    if ((i & flags) != 0)
                        switch (i) {
                        case 0x001:                                     // fin
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "FIN: 1"));
                            break;
                        case 0x002:                                     // syn
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "SYN: 1"));
                            break;
                        case 0x004:                                     // rst
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "RST: 1"));
                            break;
                        case 0x008:                                     // psh
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "PSH: 1"));
                            break;
                        case 0x010:                                     // ack
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "ACK: 1"));
                            break;
                        case 0x020:                                     // urg
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "URG: 1"));
                            break;
                        case 0x040:                                     // ecn
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "ECN: 1"));
                            break;
                        case 0x080:                                     // cwr
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "CWR: 1"));
                            break;
                        case 0x100:                                     // nonce
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "NONCE: 1"));
                            break;
                        }
                    else
                        switch (i) {
                        case 0x001:                                     // fin
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "FIN: 0"));
                            break;
                        case 0x002:                                     // syn
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "SYN: 0"));
                            break;
                        case 0x004:                                     // rst
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "RST: 0"));
                            break;
                        case 0x008:                                     // psh
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "PSH: 0"));
                            break;
                        case 0x010:                                     // ack
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "ACK: 0"));
                            break;
                        case 0x020:                                     // urg
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "URG: 0"));
                            break;
                        case 0x040:                                     // ecn
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "ECN: 0"));
                            break;
                        case 0x080:                                     // cwr
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "CWR: 0"));
                            break;
                        case 0x100:                                     // nonce
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "NONCE: 0"));
                            break;
                        }
                }
                transportlayer->addChild(flagswidget);
                transportlayer->addChild(new QTreeWidgetItem(QStringList() << "Window Size: " + QString::number(winsize)));
                transportlayer->addChild(new QTreeWidgetItem(QStringList() << "Checksum: 0x" + QString::number(checksum, 16)));
                transportlayer->addChild(new QTreeWidgetItem(QStringList() << "Urgent Pointer: " + QString::number(urgptr)));
                items.append(transportlayer);
                break;
            }
            case 0x11: {                                                // udp
                UdpPacket udppkt(pkt, 4 + ipv4pkt.getHeaderLen());
                quint16 srcPort = udppkt.getSrcPort();
                quint16 dstPort = udppkt.getDstPort();
                quint16 checksum = udppkt.getChecksum();
                QTreeWidgetItem *transportlayer = new QTreeWidgetItem(QStringList() << "User Datagram Protocol, Src Port: " + QString::number(srcPort) + ", Dst Port: " + QString::number(dstPort));
                transportlayer->addChild(new QTreeWidgetItem(QStringList() << "Source Port: " + QString::number(srcPort)));
                transportlayer->addChild(new QTreeWidgetItem(QStringList() << "Destination Port: " + QString::number(dstPort)));
                transportlayer->addChild(new QTreeWidgetItem(QStringList() << "Checksum: 0x" + QString::number(checksum, 16)));
                items.append(transportlayer);
                break;
            }
            }
            break;
        }
        }
        break;
    }
    default: {
        break;
    }
    }
    QTreeWidgetItem *rawinfo = new QTreeWidgetItem(QStringList() << "Frame " + QString::number(pkt->getNumber()) + ": " +
                                                   QString::number(pkt->getLen()) +
                                                   " bytes on wire (" + QString::number(pkt->getLen() * 8) + " bits), " +
                                                   QString::number(pkt->getCapLen()) + " bytes captured (" +
                                                   QString::number(pkt->getCapLen() * 8) + " bits) on interface " + captor.getCurDeviceName());
    QString protocolStack = pkt->getProtocolStack();
    QTreeWidgetItem *deviceInfo = new QTreeWidgetItem(QStringList() << "Interface: " + captor.getCurDeviceName());
    deviceInfo->addChild(new QTreeWidgetItem(QStringList() << "Interface name: " + captor.getCurDeviceName()));
    deviceInfo->addChild(new QTreeWidgetItem(QStringList() << "Interface description: " + captor.getCurDeviceDescription()));
    rawinfo->addChild(deviceInfo);
    rawinfo->addChild(new QTreeWidgetItem(QStringList() << "Encapsulation type: " + QString::number(linktype)));
    time_t time_sec = pkt->getTimeval().tv_sec;
    struct tm *datetime = localtime(&time_sec);
    datetime->tm_year += 1900;
    datetime->tm_mon++;
    QString datetimeStr = QString::number(datetime->tm_year) + '-' + QString::number(datetime->tm_mon) + '-' +
            QString::number(datetime->tm_mday) + ' ' + QString::number(datetime->tm_hour) + ':' + QString::number(datetime->tm_min) +
            ':' + QString::number(datetime->tm_sec) + '.' + QString::number(pkt->getTimeval().tv_usec);
    rawinfo->addChild(new QTreeWidgetItem(QStringList() << "Arrival Time: " + datetimeStr));
    rawinfo->addChild(new QTreeWidgetItem(QStringList() << "Epoch Time: " + QString::number(pkt->getTimeval().tv_sec) + '.' +
                                          QString::number(pkt->getTimeval().tv_usec) + " seconds"));
    rawinfo->addChild(new QTreeWidgetItem(QStringList() << "Frame Number: " + QString::number(pkt->getNumber())));
    rawinfo->addChild(new QTreeWidgetItem(QStringList() << "Frame Length: " + QString::number(pkt->getLen()) + " bytes (" +
                                          QString::number(pkt->getLen() * 8) + " bits)"));
    rawinfo->addChild(new QTreeWidgetItem(QStringList() << "Capture Length: " + QString::number(pkt->getCapLen()) +
                                          " bytes (" + QString::number(pkt->getCapLen() * 8) + " bits)"));
    rawinfo->addChild(new QTreeWidgetItem(QStringList() << "Protocols in frame: " + protocolStack));
    items.prepend(rawinfo);

#if DEBUG
    qDebug() << pkt->getProtocolStack();
#endif

    ui->detailedPacketView->addTopLevelItems(items);



    // show infomation by text browser
    quint64 pktlen = pkt->getCapLen();
    QString text;
    for (quint32 i = 1; i <= pktlen; i += 16) {
        QString line = QString("%1").arg(i - 1, 4, 16, QLatin1Char('0')) + "   ";
        for (quint32 j = i - 1; j < qMin(pktlen, (i + 16) - 1); j++) {
            line += QString("%1").arg(pkt->getByte(j), 2, 16, QLatin1Char('0')) + ' ';
            if ((j + 1) % 8 == 0)
                line += ' ';
        }
        if ((i + 16) > pktlen) {                                        // the last row
            while (line.size() != 60 - 3)
                line += ' ';
        }
        line += "   ";                                                  // 3
        //        qDebug() << line.size();                                      // by this get aligning position (60)
        for (quint32 z = i - 1; z < qMin(pktlen, (i + 16) - 1); z++) {
            if (pkt->getByte(z) >= 33 && pkt->getByte(z) <= 126)
                line += QChar(pkt->getByte(z));
            else
                line += "·";
            if ((z + 1) % 8 == 0)
                line += ' ';
        }
        text += line;
        if (i < pktlen)
            text += '\n';
    }
    ui->rawPacketView->setText(text);
}

void MainWindow::checkChanged(int promisc) {
    captor.setPromisc(promisc);
    updateStatusBar();
}

void MainWindow::openClicked() {
    enum confirmState state = confirm();
    switch (state) {
    case dropPackets: {
        break;
    }
    case dumpPackets: {                                                 // save packets
        PacketFileDialog dialog;
        QString filePath = dialog.getOpenPcapFileName();
        if (filePath.isEmpty())
            return;
        captor.dumpPackets(filePath);
        break;
    }
    default:
        return;                                                         // cancel operation
    }
    PacketFileDialog dialog;
    QString filePath = dialog.getOpenPcapFileName();
    if (filePath.isEmpty())                                             // filter the invalid path
        return;
    srcModel->removeRows(0, srcModel->rowCount());                      // clear table widget
    srcModel->setRowCount(0);
    ui->detailedPacketView->clear();                                    // clear tree view content
    ui->rawPacketView->clear();                                         // clear text browser content
    turnOffFilter();
    captor.readPackets(filePath);
    if (!ui->actionSave->isEnabled())                                   // if save menu is disabled, set it enabled
        ui->actionSave->setEnabled(true);
    ui->actionPackets_captured_filter->setChecked(true);
}

void MainWindow::saveClicked() {
    PacketFileDialog dialog;
    QString filePath = dialog.getSavePcapFileName();
    if (filePath.isEmpty())
        return;
    if (!captor.dumpPackets(filePath)) {
        QMessageBox::critical(nullptr, "Error", "The file being replaced has been opened by other programs!\n"
                                                "Plase make sure they are closed before this operation.");
        return;
    }
    ui->actionSave->setEnabled(false);
}

void MainWindow::aboutMeClicked() {
    QMessageBox::about(nullptr, "About me", "SIT-LDY\n1810300215       ");
}

void MainWindow::aboutMySchoolClicked() {
    QDesktopServices::openUrl(QUrl("https://www.sit.edu.cn/"));
}

void MainWindow::filterPackets() {
    QString content = ui->filter->text();
    switch (currentFilter) {
    case flowTrafficFilter:
        if (captor.getState()) {
            QMessageBox::warning(nullptr, "Warning", "Please stop the capture first before this operation!");
            return;
        }
        if (!content.isEmpty()) {
            captor.setFilterRule(content.toLower());
            captor.setHook();
            on = true;
            qInfo() << "set hook";
        }
        else {
            captor.clearHook();
            on = false;
            qInfo() << "clear hook";
        }
        updateStatusBar();
        statusBar()->showMessage("Ok, I got it!", 1300);
        break;
    case packetsFilter:
        statusBar()->showMessage("It has yet been unimplemented!", 1300);


        break;
    }
}

void MainWindow::setCurrentFilter(QAction *action)
{
    if (on)                                                             // if the filter is working
        turnOffFilter();
    if (action->objectName() == ui->actionFlow_traffic_filter->objectName() &&
            currentFilter != flowTrafficFilter) {
        currentFilter = flowTrafficFilter;
        qInfo() << "Flow Traffic Filter";
    } else if (action->objectName() == ui->actionPackets_captured_filter->objectName() &&
               currentFilter != packetsFilter) {
        currentFilter = packetsFilter;
        qInfo() << "Packets Filter";
    }
    updateStatusBar();
}

void MainWindow::saveAs()
{
    if (captor.packets.isEmpty()) {
        QMessageBox::warning(nullptr, "Error", "These aren't any packets captured!");
        return;
    }
    PacketFileDialog dialog;
    QString filePath = dialog.getSavePcapFileName();
    if (filePath.isEmpty())
        return;
    if (!captor.dumpPackets(filePath)) {
        QMessageBox::critical(nullptr, "Error", "The file being replaced has been opened by other programs!\n"
                                                "Plase make sure they are closed before this operation.");
    }
    ui->actionSave->setEnabled(false);
}

void MainWindow::openFilterRuleWebsite() {
    QDesktopServices::openUrl(QUrl("https://npcap.com/guide/wpcap/pcap-filter.html"));
}

void MainWindow::errorHandler(QString message) {
    qInfo("error!");
    QMessageBox::warning(nullptr,
                         "Error",
                         message +
                         "\nPlease put the correct filter rule into the captor!",
                         QMessageBox::StandardButton::Ok);
}

void MainWindow::ready() {
    srcModel->removeRows(0, srcModel->rowCount());
    //        srcModel->clearContents();                            // clear packet list content (except for header items)
    srcModel->setRowCount(0);
    if (openedWindows.size() != 0) {
        if (!captor.getArePacketsSaved()) {                         // if detecte unsaved packet, add preffix before its title
            for (PacketDetailView *window : openedWindows)
                window->setWindowTitle("[no packet file] " + window->windowTitle());
        }
        for (PacketDetailView *window : openedWindows)
            unwantedWindows.append(window);
        openedWindows.clear();
    }
    setWindowTitle(title + " [running at " + captor.getCurDeviceDescription() + ']');
    ui->btnTrigger->setIcon(QIcon(":/stop_icon.png"));
    ui->actionOpen->setEnabled(false);
    ui->actionSave->setEnabled(false);
    ui->actionSave_as->setEnabled(false);
    ui->deviceListView->setEnabled(false);
    ui->btnReload->setEnabled(false);
    ui->promisc->setEnabled(false);
    ui->actionFlow_traffic_filter->setEnabled(false);
    ui->actionPackets_captured_filter->setEnabled(false);
    if (currentFilter == flowTrafficFilter)
        ui->filter->setEnabled(false);
}

void MainWindow::done() {
    setWindowTitle(title);
    ui->btnTrigger->setIcon(QIcon(":/start_icon.png"));
    ui->actionOpen->setEnabled(true);
    ui->actionSave->setEnabled(true);
    ui->actionSave_as->setEnabled(true);
    ui->deviceListView->setEnabled(true);
    ui->btnReload->setEnabled(true);
    ui->promisc->setEnabled(true);
    ui->actionFlow_traffic_filter->setEnabled(true);
    ui->actionPackets_captured_filter->setEnabled(true);
    if (!ui->filter->isEnabled())
        ui->filter->setEnabled(true);
}

void MainWindow::closeEvent(QCloseEvent *event) {
    enum confirmState state = confirm();                                // get close state
    switch (state) {
    case dumpPackets: {                                                 // save the unsaved packets and terminate this program
        PacketFileDialog dialog;
        QString filePath = dialog.getSavePcapFileName();
        if (filePath.isEmpty()) {                                       // cancelled save file dialog and operation failed
            /* the method block is at below (i.e. equivalent to case cancel) */
        } else {
            if (captor.getState())
                ui->btnTrigger->click();
            captor.dumpPackets(filePath);
            break;
        }
    }
    case cancel: {
        event->ignore();                                                // cancel this operation and back to the calling site
        return;
    }
    default: {                                                          // terminate this program directly (dropping the unsaved packets)
        if (captor.getState())                                          // terminate packet capture
            ui->btnTrigger->click();
        break;
    }
    }

    if (openedWindows.size() != 0) {
        for (PacketDetailView *window : openedWindows) {
            if (window->isActiveWindow())
                window->close();
            delete window;
        }
        openedWindows.clear();
    }
    if (unwantedWindows.size() != 0) {
        for (PacketDetailView *window : unwantedWindows) {
            if (window->isActiveWindow())
                window->close();
            delete window;
        }
        unwantedWindows.clear();
    }
}

void MainWindow::showEvent(QShowEvent *event) {
    /* load the necessary parameters */

    // menu bar
    ui->actionSave->setEnabled(false);
    ui->actionSave_as->setEnabled(false);
    ui->actionFlow_traffic_filter->setChecked(true);                        // we just set it checked and it have yet been not triggered!
    emit group.triggered(ui->actionFlow_traffic_filter);                    // simulate a triggering

    // combo box
    if (captor.devices.size() != 0) {
        ui->deviceListView->clear();                                        // clear the old items
        for (int i = 0; i < captor.devices.size(); i++) {
            ui->deviceListView->addItem(captor.devices[i]->description);
            ui->deviceListView->setItemData(i, Qt::AlignCenter, Qt::TextAlignmentRole);
        }
    }
    ui->deviceListView->setFont(deviceListViewFont);

    // table widget
    QStringList sl{"No", "Time", "Source", "Destination", "Length", "Protocol", "Info"};
    srcModel->setColumnCount(sl.size());
    srcModel->setHorizontalHeaderLabels(sl);
    ui->packetListView->verticalHeader()->setSectionResizeMode(QHeaderView::Fixed);
    // set height of rows
    ui->packetListView->verticalHeader()->setDefaultSectionSize(13);
    // set width of columns
    ui->packetListView->setColumnWidth(0, 50);   // number
    ui->packetListView->setColumnWidth(1, 100);  // arrtival time
    ui->packetListView->setColumnWidth(2, 230);  // src
    ui->packetListView->setColumnWidth(3, 230);  // dst
    ui->packetListView->setColumnWidth(4, 100);  // len
    ui->packetListView->setColumnWidth(5, 100);  // protocol
    ui->packetListView->setColumnWidth(6, 1000); // info
    ui->packetListView->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ui->packetListView->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->packetListView->setSelectionMode(QAbstractItemView::SingleSelection);
    ui->packetListView->verticalHeader()->hide();
    ui->packetListView->horizontalHeader()->setStretchLastSection(true);
    ui->packetListView->setGridStyle(Qt::NoPen);
    ui->packetListView->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    ui->packetListView->horizontalHeader()->setFont(packetListViewHeaderFont);
    ui->packetListView->setFont(packetListViewFont);
    ui->packetListView->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
    ui->packetListView->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);

    // tree widget
    ui->detailedPacketView->setHeaderHidden(true);
    ui->detailedPacketView->header()->hide();
    ui->detailedPacketView->setFont(packetDetailViewFont);

    // text browser
    ui->rawPacketView->setFont(rawPacketViewFont);
    ui->rawPacketView->setWordWrapMode(QTextOption::NoWrap);

    // text box
    ui->filter->setFont(textBoxFont);

    // taskbar
    updateStatusBar();
}

enum MainWindow::confirmState MainWindow::confirm() {
    if (!captor.getIsEmpty() && !captor.getArePacketsSaved()) {   // if packets collection is not empty and they are unsaved
        QMessageBox::StandardButton checkButton = QMessageBox::question(this,
                                                                        "Detected unsaved packets",
                                                                        "You have packets unsaved.\nWould you like to save them before this operation?",
                                                                        QMessageBox::StandardButton::Yes |
                                                                        QMessageBox::StandardButton::No |
                                                                        QMessageBox::StandardButton::Cancel);
        if (checkButton == QMessageBox::Yes)
            return dumpPackets;
        else if (checkButton == QMessageBox::Cancel)
            return cancel;
    }
    return dropPackets;
}

void MainWindow::updateStatusBar() {
    QString content = qTemplate.arg(description);
    switch (currentFilter) {
    case packetsFilter:
        content = content.arg("Packets Filter");
        break;
    case flowTrafficFilter:
        content = content.arg("Flow Traffic Filter");
        break;
    default:
        content = content.arg("Unknown");
        break;
    }
    content = content.arg(on ? "On" : "Off");
    content = content.arg(captor.getPromisc() ? "On": "Off");
    info->setText(content);
}

void MainWindow::turnOffFilter() {
    switch (currentFilter) {
    case flowTrafficFilter:
        ui->filter->clear();
        emit ui->filter->returnPressed();
        break;
    case packetsFilter:

        break;
    default:  // no default
        break;
    }

    on = false;
    updateStatusBar();
}
