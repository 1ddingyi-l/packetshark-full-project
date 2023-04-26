#ifndef PKTF_H
#define PKTF_H

#include <QObject>

typedef struct {
    quint8       dst[6];
    quint8       src[6];
    quint16      type;
} *etherhdr;

typedef struct {
    quint32      family;
} *nullhdr;

typedef struct {
    quint8       version_hdrlen;
    quint8       sertype;
    quint16      pktlen;
    quint16      iden;
    quint16      offset;
    quint8       ttl;
    quint8       protocol;
    quint16      checksum;
    quint8       src[4];
    quint8       dst[4];
    quint32      *opts;
} *ipv4hdr;

typedef struct {
    quint32      ver_ds_fl;
    quint16      payloadlen;
    quint8       nexthdr;
    quint8       hoplimit;
    quint8       src[16];
    quint8       dst[16];
} *ipv6hdr;

typedef struct {
    quint16      type;
    quint16      protocol;
    quint8       haddrlen;
    quint8       paddrlen;
    quint16      opcode;
    quint8       srchaddr[6];
    quint8       srcpaddr[4];
    quint8       dsthaddr[6];
    quint8       dstpaddr[4];
} *arp;

typedef struct {
    quint8       type;
    quint8       code;
    quint16      checksum;
    quint16      iden;
    quint16      seq;
} *icmp;

typedef struct {
    quint8       type;
    quint8       maxresptime;
    quint16      checksum;
    quint8       groupaddr[4];
} *igmp;                                    // igmpv2

typedef struct {
    quint8      type;
    quint8      maxresptime;
    quint16     checksum;
    quint8      groupaddr[4];
    quint8      rsq;                        // reserved + s + qrv
    quint8      qqic;
    quint16     nos;
    quint32     *srcaddr;
} *igmpv3;                                  // igmpv3

typedef struct {
    quint16      src;
    quint16      dst;
    quint32      seqN;
    quint32      ackN;
    quint8       hdrlen;                    // hdrlen + flags
    quint8       flags;                     // continued flags
    quint16      winsize;
    quint16      checksum;
    quint16      urgptr;
    quint32      *options;
} *tcphdr;

typedef struct {
    quint16      src;
    quint16      dst;
    quint16      payloadlen;
    quint16      checksum;
} *udphdr;

typedef struct {
    quint16      iden;
    quint16      flags;
    quint16      question;
    quint16      anwser;
    quint16      authority;
    quint16      additional;
    quint16      type;
    quint16      clas;
} *dns;

typedef struct {
    quint32     family;
} *nullpkthdr;

#endif // PKTF_H
