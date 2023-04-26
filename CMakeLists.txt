cmake_minimum_required(VERSION 3.5)
# for project info
project(packetshark
        VERSION 0.1
        LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
# for qt configuration
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_PREFIX_PATH D:/Qt/6.4.2/mingw_64)
find_package(Qt6 COMPONENTS REQUIRED Core Gui Widgets)
# for jetbrains fleet
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
# import external libraries
include_directories(npcap-sdk-1.12/Include)
link_directories(npcap-sdk-1.12/Lib/x64)

set(PROJECT_SOURCES
        main.cpp
        mainwindow.cpp
        mainwindow.h
        mainwindow.ui
        packet.h
        packet.cpp
        packetcaptor.h
        packetcaptor.cpp
        resources.qrc
        pktf.h
        ethernetpacket.h
        ethernetpacket.cpp
        ipv4packet.h
        ipv4packet.cpp
        ipv6packet.h
        ipv6packet.cpp
        arppacket.h
        arppacket.cpp
        igmppacket.h
        igmppacket.cpp
        igmpv3packet.h
        igmpv3packet.cpp
        icmppacket.h
        icmppacket.cpp
        tcppacket.h
        tcppacket.cpp
        udppacket.h
        udppacket.cpp
        packetdetailview.h
        packetdetailview.cpp
        packetdetailview.ui
        packetfiledialog.h
        packetfiledialog.cpp
        nullpacket.h
        nullpacket.cpp
        packetfilterproxymodel.h
        packetfilterproxymodel.cpp
)

add_executable(${PROJECT_NAME} ${PROJECT_SOURCES} app.rc)

target_link_libraries(${PROJECT_NAME} PRIVATE Qt6::Widgets Qt6::Core Qt6::Gui wpcap packet ws2_32)
