#include "packetcaptor.h"

PacketCaptor::PacketCaptor() {
    reloadDevices();
    qInfo() << "Default mode: Promiscuous";
}

PacketCaptor::~PacketCaptor() {
    clearPackets();
    clearDevices();
}

void PacketCaptor::clearPackets() {
    for (Packet *packet : packets)
        delete packet;
    packets.clear();                                                // remove all old packets from packet collection
}

void PacketCaptor::clearDevices() {
    if (devs == nullptr)
        return;
    pcap_freealldevs(devs);
    devs = nullptr;
}

bool PacketCaptor::dumpPackets(QString target) {
    if (!isRunning && packets.size() != 0) {                        // if the packets number is not zero, the collection have been
                                                                    // dumpped to savefile (i.e. defaultPacketFile exists)
        return movePacketsFileTo(target);
    }
    else
        return false;
}

void PacketCaptor::deleteDefaultDumpFile() {
    const fs::path defaultPath(defaultFilePath.toStdString());
    if (fs::exists(defaultPath))
        fs::remove(defaultPath);                                        // delete old file
}

bool PacketCaptor::readPackets(QString file) {
    if (!fs::exists(file.toStdString()))
        return false;
    if (packets.size() != 0)                                            // clear old packets
        clearPackets();
    pcap_t *cdev = pcap_open_offline(file.toLocal8Bit(),
                                     errBuf);
    struct pcap_pkthdr *pkthdr = nullptr;
    const u_char *rawpkt = nullptr;
    qint32 link_t = pcap_datalink(cdev);
    quint64 number = 1;
    while (true) {
        int n = pcap_next_ex(cdev,
                             &pkthdr,
                             &rawpkt);
        if (n < 0)                                                      // until EOF is reached
            break;
        Packet *pkt = new Packet(number++,
                                 pkthdr,
                                 link_t,
                                 rawpkt,
                                 0,
                                 "unknown",
                                 "unknown");
        emit packetArrival(pkt);
        packets.append(pkt);
    }

    arePacketsSaved = true;
    pcap_close(cdev);                                                   // release the device descriptor
    cdev = nullptr;

    return true;
}

bool PacketCaptor::getState() const {
    return isRunning;
}

void PacketCaptor::stop() {
    if (curdev == nullptr || curdevP == nullptr)                        // invalid operation
        return;
    isRunning = false;
    wait();                                                             // waiting for the termination of the thread
    arePacketsSaved = getIsEmpty() ? true : false;                      // get that new packets that're unsaved
    emit captureDone();                                                 // notify the main thread updating ui
}

void PacketCaptor::setDevice(pcap_if_t *dev) {
    curdev = dev;
    if (dev->addresses != nullptr) {
        netmask = ((struct sockaddr_in *)(dev->addresses->netmask))->sin_addr.S_un.S_addr;
    } else {
        netmask = 0xffffffff;
    }
    qInfo() << netmask;
}

bool PacketCaptor::reloadDevices() {
    if (devs != nullptr) {
        pcap_freealldevs(devs);
        devs = nullptr;
        devices.clear();
    }
    int n = pcap_findalldevs(&devs,
                             errBuf);
    if (n < 0) {
        devs = nullptr;
        return false;
    }
    for (pcap_if_t *d = devs; d != nullptr; d = d->next) {
        qInfo() << d->description;
        devices.append(d);
    }
    qInfo() << "Refleshing done";
    return true;
}

bool PacketCaptor::movePacketsFileTo(QString filePath) {
    fs::path src = defaultFilePath.toStdString(),
             dst = filePath.toStdString();
    if (fs::exists(dst)) {
        try {
            fs::remove(dst);
        } catch (fs::filesystem_error error) {
            return false;
        }
    }
                                                    // if there is a old one, delete it!
    fs::copy(src,
             dst);
    return arePacketsSaved = true;
}

bool PacketCaptor::getArePacketsSaved() const {
    if (isRunning)
        return packets.isEmpty();
    return arePacketsSaved;
}

void PacketCaptor::setPromisc(int promisc) {
    if (promisc)
        qInfo() << "Promiscuous mode";
    else
        qInfo() << "Normal mode";
    openFlag = promisc;
}

bool PacketCaptor::getPromisc() const {
    return openFlag;
}

void PacketCaptor::setHook() {
    hook = true;
}

void PacketCaptor::clearHook() {
    filterRule = "";
    hook = false;
}

QString PacketCaptor::getCurDeviceName() const {
    if (curdev != nullptr)
        return curdev->name;
    return "Unknown device";
}

QString PacketCaptor::getCurDeviceDescription() const {
    if (curdev != nullptr)
        return curdev->description;
    return "null";
}

bool PacketCaptor::getIsEmpty() const {
    return packets.isEmpty();
}

void PacketCaptor::setFilterRule(QString filterRule) {
    this->filterRule.clear();
    this->filterRule = filterRule;
}

void PacketCaptor::run() {
    if (curdev == nullptr)                                              // invalid argument
        return;
    curdevP = pcap_open_live(curdev->name,                              // device name
                             snaplen,                                   // max number of packets to be captured
                             openFlag,                                  // whether stay promiscuous
                             timeout,
                             errBuf);                                   // error information (when there is exception)
    if (curdevP == nullptr)                                             // exceptional condition
        return;
    if (hook) {
        struct bpf_program fcode;
        if (pcap_compile(curdevP,
                         &fcode,                                        // it will be filled by the pcap_compile subroutine if successful
                         filterRule.toStdString().c_str(),              // filter expression
                         1,                                             // optimize the resulting code
                         netmask                                        // the netmask of the network device
                         ) < 0) {                                       // compile the filter
            pcap_close(curdevP);
            curdevP = nullptr;
            emit compileError("Filter-rule compiling error!");
            return;
        }
        if (pcap_setfilter(curdevP, &fcode) < 0) {                      // associate the filter we compile with a capture session in the kernel
            pcap_close(curdevP);
            curdevP = nullptr;
            emit compileError("Cannot set the filter!");
            return;
        }
    }

    emit readyForCapture();                                             // notify the main thread updating ui

    if (packets.size() != 0)                                            // not the first time to start capture
        clearPackets();
    deleteDefaultDumpFile();                                            // remove last dump file
    quint64 number = 1;                                                 // to number the packet
    isRunning = true;
    qint32 link_t = pcap_datalink(curdevP);
    struct pcap_pkthdr *pkthdr = static_cast<struct pcap_pkthdr *>(nullptr);
    const u_char *raw = static_cast<const u_char *>(nullptr);
    dump = pcap_dump_open(curdevP,                                      // open save file to which to write packets
                          defaultFilePath.toLocal8Bit());
    while (isRunning) {
        qint32 n = pcap_next_ex(curdevP,
                                &pkthdr,
                                &raw);
        if (n == 0)
            continue;
        pcap_dump((u_char *)dump,                                       // dump packets into the savefile
                  pkthdr,
                  raw);                                                 // dump packets to default file (by defaultFilePath)
                                                                        /* if we don't need dumping packets, we could delete the file
                                                                           after a packet capture */
        Packet *pkt = new Packet(number++,                              // packet number
                                 pkthdr,                                // packet original header
                                 link_t,                                // the type of link that packets are from
                                 raw,                                   // packet raw data
                                 0,                                     // packet offset (link packet is zero)
                                 QString(curdev->name),
                                 QString(curdev->description));
        emit packetArrival(pkt);
        packets.append(pkt);
    }

    pcap_dump_close(dump);                                              // close dumper before stopping this capture
    dump = nullptr;                                                     // there is a problem here
    pcap_close(curdevP);                                                // close device
    curdevP = nullptr;
}
