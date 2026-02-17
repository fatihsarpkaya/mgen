#ifndef _MGEN_PRAGUE_TRANSPORT
#define _MGEN_PRAGUE_TRANSPORT

#include "mgenTransport.h"
#include "prague_cc.h"
#include "pkt_format.h"

/**
 * @class MgenPragueTransport
 *
 * @brief MGEN transport using UDP Prague congestion control.
 *
 * Uses PragueCC library (from udp_prague) for L4S-compatible
 * congestion control over UDP. MGEN flow patterns define the
 * offered load; PragueCC limits the actual send rate based on
 * ECN/loss feedback from the receiver (udp_prague_receiver).
 *
 * Wire-compatible with the standalone udp_prague_sender/receiver.
 */
class MgenPragueTransport : public MgenSocketTransport
{
  public:
    MgenPragueTransport(Mgen& mgen, UINT16 port, const ProtoAddress& dstAddr);
    ~MgenPragueTransport();

    bool Open(ProtoAddress::Type addrType, bool bindOnOpen);
    void OnEvent(ProtoSocket& theSocket, ProtoSocket::Event theEvent);
    MessageStatus SendMessage(MgenMsg& theMsg, const ProtoAddress& dstAddr);
    bool Listen(UINT16 port, ProtoAddress::Type addrType, bool bindOnOpen);
    bool IsConnected() { return true; }

  private:
    // ECN-aware send/recv using raw fd (mirrors udp_prague/udpsocket.cpp)
    ssize_t SendToWithEcn(const char* buf, size_t len,
                          const ProtoAddress& dstAddr, ecn_tp ecn);
    ssize_t RecvFromWithEcn(char* buf, size_t maxLen,
                            ProtoAddress& srcAddr, ecn_tp& ecn);
    void    ProcessPendingACKs();

    // Prague CC (imported from udp_prague library)
    PragueCC   pragueCC;
    count_tp   seqnr;
    count_tp   inflight;
    rate_tp    pacing_rate;
    count_tp   packet_window;
    count_tp   packet_burst;
    size_tp    prague_packet_size;
    time_tp    nextSend;

    // Sender-side packet tracking for ACK processing
    pktsend_tp pkts_stat[PKT_BUFFER_SIZE];
    count_tp   pkts_lost;
};

#endif // _MGEN_PRAGUE_TRANSPORT
