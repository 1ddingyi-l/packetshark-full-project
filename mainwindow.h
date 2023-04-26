#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#define DEBUG 1

#include <sys/time.h>

#include <QAbstractItemModel>
#include <QAction>
#include <QActionGroup>
#include <QCloseEvent>
#include <QDesktopServices>
#include <QFileDialog>
#include <QItemSelection>
#include <QLabel>
#include <QMainWindow>
#include <QMessageBox>
#include <QShowEvent>
#include <QStandardItemModel>
#include <QTableWidgetItem>
#include <QtGlobal>
#include <QUrl>
#include <QVector>

#include "packetcaptor.h"
#include "pktf.h"
#include "packetdetailview.h"
#include "packetfiledialog.h"
#include "packetfilterproxymodel.h"

#include "ethernetpacket.h"
#include "ipv4packet.h"
#include "ipv6packet.h"
#include "arppacket.h"
#include "icmppacket.h"
#include "igmppacket.h"
#include "igmpv3packet.h"
#include "tcppacket.h"
#include "udppacket.h"
#include "nullpacket.h"

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

protected slots:
    void                                triggerAction();
    void                                reloadDeviceList();
    void                                setDevice(int);
    void                                parsePacket(Packet *);
    void                                showPacketDetail(const QItemSelection &, const QItemSelection &);
    void                                showPacketDetailWindow(const QModelIndex &);
    void                                checkChanged(int);
    void                                openClicked();
    void                                saveClicked();
    void                                aboutMeClicked();
    void                                aboutMySchoolClicked();
    void                                filterPackets();
    void                                setCurrentFilter(QAction *);
    void                                saveAs();
    void                                openFilterRuleWebsite();
    void                                errorHandler(QString);
    void                                ready();
    void                                done();


private:
    enum confirmState {
        dumpPackets,
        dropPackets,
        cancel,
    };

    enum filters {
        packetsFilter,
        flowTrafficFilter
    };

    void                                closeEvent(QCloseEvent *) override;
    void                                showEvent(QShowEvent *) override;
    enum confirmState                   confirm();
    void                                updateStatusBar();
    void                                turnOffFilter();

    Ui::MainWindow                      *ui;
    PacketCaptor                        captor;
    struct timeval                      captureStartingTime;
    const QString                       title = "Packetshark";
    QVector<PacketDetailView *>         unwantedWindows;
    QVector<PacketDetailView *>         openedWindows;
    PacketFilterProxyModel              *model;
    QStandardItemModel                  *srcModel;
    QActionGroup                        group;
    QString                             description;
    enum filters                        currentFilter = packetsFilter;
    bool                                on = false;  // 是否开启过滤
    QString                             qTemplate = "   Device Interface: %1 | Filter Mode: %2 [%3] | Promiscuous: %4";
    QLabel                              *info;

    QFont                               deviceListViewFont{"Consolas", 11};
    QFont                               packetListViewHeaderFont{"Consolas", 11};
    QFont                               packetListViewFont{"Consolas", 11};
    QFont                               packetDetailViewFont{"Consolas", 12};
    QFont                               rawPacketViewFont{"Consolas", 12};
    QFont                               textBoxFont{"Consolas", 11};
};
#endif // MAINWINDOW_H
