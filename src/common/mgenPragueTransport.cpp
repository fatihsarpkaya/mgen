// mgenPragueTransport.cpp:
// Glue between MGEN traffic patterns and PragueCC (UDP Prague) congestion control.
// PragueCC is imported as a library from the udp_prague repo -- not copied.
// The receiver side uses the existing udp_prague_receiver binary unchanged.

#include "mgen.h"
#include "mgenPragueTransport.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>

// Platform-specific cmsg type for receiving ECN/TOS
#ifdef __linux__
#define IP_RECV_CMSG_TYPE  IP_TOS
#define IPV6_RECV_CMSG_TYPE IPV6_TCLASS
#elif __APPLE__
#define IP_RECV_CMSG_TYPE  IP_RECVTOS
#define IPV6_RECV_CMSG_TYPE IPV6_RECVTCLASS
#else
#define IP_RECV_CMSG_TYPE  IP_TOS
#define IPV6_RECV_CMSG_TYPE IPV6_TCLASS
#endif

#define ECN_MASK 0x03

// ---------------------------------------------------------------
// Construction / Destruction
// ---------------------------------------------------------------

MgenPragueTransport::MgenPragueTransport(Mgen&               theMgen,
                                         UINT16              thePort,
                                         const ProtoAddress& theDstAddr)
  : MgenSocketTransport(theMgen, PRAGUE, thePort, theDstAddr),
    pragueCC(PRAGUE_INITMTU, 0, 0, PRAGUE_INITRATE,
             PRAGUE_INITWIN, PRAGUE_MINRATE, PRAGUE_MAXRATE),
    seqnr(0), inflight(0),
    pacing_rate(0), packet_window(0), packet_burst(0),
    prague_packet_size(0), nextSend(0),
    pkts_lost(0)
{
    socket.SetListener(this, &MgenPragueTransport::OnEvent);
    memset(pkts_stat, 0, sizeof(pkts_stat));
}

MgenPragueTransport::~MgenPragueTransport()
{
}

// ---------------------------------------------------------------
// Open -- base socket open + enable ECN receive
// ---------------------------------------------------------------

bool MgenPragueTransport::Open(ProtoAddress::Type addrType, bool bindOnOpen)
{
    if (!MgenSocketTransport::Open(addrType, bindOnOpen))
    {
        DMSG(0, "MgenPragueTransport::Open() base socket open failed\n");
        return false;
    }

    // Enable receiving ECN/TOS on incoming packets
    int set = 1;
    int fd = (int)socket.GetHandle();
    if (addrType == ProtoAddress::IPv6)
    {
#ifdef HAVE_IPV6
        if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVTCLASS, &set, sizeof(set)) < 0)
            DMSG(0, "MgenPragueTransport::Open() warning: setsockopt(IPV6_RECVTCLASS) failed\n");
#endif
    }
    else
    {
        if (setsockopt(fd, IPPROTO_IP, IP_RECVTOS, &set, sizeof(set)) < 0)
            DMSG(0, "MgenPragueTransport::Open() warning: setsockopt(IP_RECVTOS) failed\n");
    }

    // Initialize Prague CC state
    pragueCC.GetCCInfo(pacing_rate, packet_window, packet_burst, prague_packet_size);
    nextSend = pragueCC.Now();

    DMSG(PL_INFO, "MgenPragueTransport::Open() Prague CC initialized "
         "(rate=%llu B/s, window=%d, burst=%d)\n",
         (unsigned long long)pacing_rate, packet_window, packet_burst);

    return true;
}

bool MgenPragueTransport::Listen(UINT16 port, ProtoAddress::Type addrType, bool bindOnOpen)
{
    if (!MgenSocketTransport::Listen(port, addrType, bindOnOpen))
        return false;
    return StartInputNotification();
}

// ---------------------------------------------------------------
// ECN-aware send using sendmsg (mirrors udp_prague/udpsocket.cpp)
// ---------------------------------------------------------------

ssize_t MgenPragueTransport::SendToWithEcn(const char*         buf,
                                           size_t              len,
                                           const ProtoAddress& dstAddr,
                                           ecn_tp              ecn)
{
    int fd = (int)socket.GetHandle();

    struct iovec iov;
    iov.iov_base = (void*)buf;
    iov.iov_len  = len;

    // Set destination address from ProtoAddress
    struct sockaddr_storage ss;
    memset(&ss, 0, sizeof(ss));
    memcpy(&ss, &dstAddr.GetSockAddr(),
           (dstAddr.GetType() == ProtoAddress::IPv6)
               ? sizeof(struct sockaddr_in6)
               : sizeof(struct sockaddr_in));

    char ctrl[CMSG_SPACE(sizeof(int))];
    memset(ctrl, 0, sizeof(ctrl));

    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_name       = &ss;
    msg.msg_namelen    = (dstAddr.GetType() == ProtoAddress::IPv6)
                             ? sizeof(struct sockaddr_in6)
                             : sizeof(struct sockaddr_in);
    msg.msg_iov        = &iov;
    msg.msg_iovlen     = 1;
    msg.msg_control    = ctrl;
    msg.msg_controllen = sizeof(ctrl);

    // Fill ECN control message
    struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    if (dstAddr.GetType() == ProtoAddress::IPv6)
    {
        cmsg->cmsg_level = IPPROTO_IPV6;
        cmsg->cmsg_type  = IPV6_TCLASS;
    }
    else
    {
        cmsg->cmsg_level = IPPROTO_IP;
        cmsg->cmsg_type  = IP_TOS;
    }
    int ecn_val = (int)ecn & ECN_MASK;
    memcpy(CMSG_DATA(cmsg), &ecn_val, sizeof(ecn_val));

    return sendmsg(fd, &msg, 0);
}

// ---------------------------------------------------------------
// ECN-aware recv using recvmsg (mirrors udp_prague/udpsocket.cpp)
// ---------------------------------------------------------------

ssize_t MgenPragueTransport::RecvFromWithEcn(char*         buf,
                                             size_t        maxLen,
                                             ProtoAddress& srcAddr,
                                             ecn_tp&       ecn)
{
    int fd = (int)socket.GetHandle();

    struct iovec iov;
    iov.iov_base = buf;
    iov.iov_len  = maxLen;

    struct sockaddr_storage ss;
    char ctrl[CMSG_SPACE(sizeof(int))];
    memset(ctrl, 0, sizeof(ctrl));

    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_name       = &ss;
    msg.msg_namelen    = sizeof(ss);
    msg.msg_iov        = &iov;
    msg.msg_iovlen     = 1;
    msg.msg_control    = ctrl;
    msg.msg_controllen = sizeof(ctrl);

    ssize_t r = recvmsg(fd, &msg, MSG_DONTWAIT);
    if (r <= 0)
        return r;

    // Set source address
    srcAddr.SetSockAddr(*((struct sockaddr*)&ss));

    // Extract ECN from control messages
    ecn = ecn_not_ect;
    for (struct cmsghdr* c = CMSG_FIRSTHDR(&msg); c != NULL;
         c = CMSG_NXTHDR(&msg, c))
    {
        if ((c->cmsg_level == IPPROTO_IP && c->cmsg_type == IP_RECV_CMSG_TYPE) ||
            (c->cmsg_level == IPPROTO_IPV6 && c->cmsg_type == IPV6_RECV_CMSG_TYPE))
        {
            int tos_val;
            memcpy(&tos_val, CMSG_DATA(c), sizeof(tos_val));
            ecn = (ecn_tp)(tos_val & ECN_MASK);
            break;
        }
    }

    return r;
}

// ---------------------------------------------------------------
// ProcessPendingACKs -- non-blocking check for ACK packets
// ---------------------------------------------------------------

void MgenPragueTransport::ProcessPendingACKs()
{
    char buffer[BUFFER_SIZE];
    ProtoAddress srcAddr;
    ecn_tp rcv_ecn;

    while (true)
    {
        ssize_t len = RecvFromWithEcn(buffer, sizeof(buffer), srcAddr, rcv_ecn);
        if (len <= 0)
            break;

        uint8_t type = (uint8_t)buffer[0];

        if (type == PKT_ACK_TYPE && len >= (ssize_t)sizeof(ackmessage_t))
        {
            ackmessage_t& ack = *(ackmessage_t*)buffer;
            ack.get_stat(pkts_stat, pkts_lost);
            pragueCC.PacketReceived(ack.timestamp, ack.echoed_timestamp);
            pragueCC.ACKReceived(ack.packets_received, ack.packets_CE,
                                 ack.packets_lost, seqnr, ack.error_L4S,
                                 inflight);
            pragueCC.GetCCInfo(pacing_rate, packet_window, packet_burst,
                               prague_packet_size);
        }
        else if (type == RFC8888_ACK_TYPE && len >= (ssize_t)sizeof(uint8_t))
        {
            rfc8888ack_t& rfc_ack = *(rfc8888ack_t*)buffer;
            time_tp now = pragueCC.Now();
            time_tp sendtime[PKT_BUFFER_SIZE] = {0};
            time_tp pkts_rtt[REPORT_SIZE] = {0};
            count_tp pkts_received = 0, pkts_CE = 0, rfc_lost = 0;
            bool err_L4S = false;
            count_tp last_ackseq = 0;

            uint16_t num_rtt = rfc_ack.get_stat(now, sendtime, pkts_rtt,
                                                 pkts_received, rfc_lost,
                                                 pkts_CE, err_L4S,
                                                 pkts_stat, last_ackseq);
            if (num_rtt)
            {
                pragueCC.RFC8888Received(num_rtt, pkts_rtt);
                pragueCC.ACKReceived(pkts_received, pkts_CE, rfc_lost,
                                     seqnr, err_L4S, inflight);
                pragueCC.GetCCInfo(pacing_rate, packet_window, packet_burst,
                                   prague_packet_size);
            }
        }
    }
}

// ---------------------------------------------------------------
// SendMessage -- MGEN flow calls this; we gate it through PragueCC
// ---------------------------------------------------------------

MessageStatus MgenPragueTransport::SendMessage(MgenMsg& theMsg,
                                               const ProtoAddress& dstAddr)
{
    // 1. Check for any pending ACKs (non-blocking)
    ProcessPendingACKs();

    // 2. Get latest CC parameters
    pragueCC.GetCCInfo(pacing_rate, packet_window, packet_burst, prague_packet_size);

    // 3. Check congestion window
    if (inflight >= packet_window)
        return MSG_SEND_BLOCKED;

    // 4. Check pacing
    time_tp now = pragueCC.Now();
    if (nextSend - now > 0)
        return MSG_SEND_BLOCKED;

    // 5. Determine packet size from MGEN flow pattern
    size_t pkt_size = theMsg.GetMsgLen();
    if (pkt_size < sizeof(datamessage_t))
        pkt_size = sizeof(datamessage_t);
    if (pkt_size > BUFFER_SIZE)
        pkt_size = BUFFER_SIZE;

    // 6. Build packet: [datamessage_t header][dummy payload]
    UINT32 txBuffer[BUFFER_SIZE / 4];
    memset(txBuffer, 0, pkt_size);
    datamessage_t& data_msg = *(datamessage_t*)txBuffer;

    ecn_tp snd_ecn;
    pragueCC.GetTimeInfo(data_msg.timestamp, data_msg.echoed_timestamp, snd_ecn);
    data_msg.seq_nr = ++seqnr;
    data_msg.hton();

    // 7. Send with ECN marking
    ssize_t sent = SendToWithEcn((const char*)txBuffer, pkt_size, dstAddr, snd_ecn);
    if (sent <= 0)
    {
        seqnr--;
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS)
            return MSG_SEND_BLOCKED;
        DMSG(PL_WARN, "MgenPragueTransport::SendMessage() sendmsg error: %s\n",
             GetErrorString());
        return MSG_SEND_FAILED;
    }

    // 8. Update CC tracking state
    inflight++;
    pkts_stat[seqnr % PKT_BUFFER_SIZE] = snd_sent;

    // 9. Update pacing for next send
    if (pacing_rate > 0)
        nextSend = now + (time_tp)(pkt_size * 1000000 / pacing_rate);
    else
        nextSend = now + 1;

    // 10. Log the send event
    LogEvent(SEND_EVENT, &theMsg, theMsg.GetTxTime(), txBuffer);

    return MSG_SEND_OK;
}

// ---------------------------------------------------------------
// OnEvent -- ProtoSocket notification (ACK arrived, or send ready)
// ---------------------------------------------------------------

void MgenPragueTransport::OnEvent(ProtoSocket&       theSocket,
                                  ProtoSocket::Event theEvent)
{
    switch (theEvent)
    {
    case ProtoSocket::RECV:
    {
        // ACKs arrived -- process them and try to send pending messages
        ProcessPendingACKs();
        SendPendingMessage();
        break;
    }
    case ProtoSocket::SEND:
    {
        SendPendingMessage();
        break;
    }
    default:
        DMSG(0, "MgenPragueTransport::OnEvent() unexpected event: %d\n", theEvent);
        break;
    }
}
