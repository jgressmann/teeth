/* SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2024 Jean Gressmann <jean@0x42.de>
 *
 */


#ifndef TEETH_H
#define TEETH_H

#if defined(__GNUC__) || defined(_MSC_VER)
#pragma once
#endif

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TEETH_PROTOCOL_VERSION 1
#define TEETH_MAX_ETHER_PACKET_SIZE (1944-16) /* save 16 bytes per tx slot */

#define TEETH_BUFFER_SIZE (sizeof(struct teeth_eth_rx_hdr) + TEETH_MAX_ETHER_PACKET_SIZE)

enum teeth_msg_type {
    /* echo request / response */
    TEETH_MT_ECHO,
    /* RX frame send from server to client */
    TEETH_MT_ETH_RX,
    /* Frame transmission request from client to server */
    TEETH_MT_ETH_TX_REQ,
    /* Tx frame transmission result from server to client */
    TEETH_MT_ETH_TX_RES,
    /* Ethernet device stats from server to client */
    TEETH_MT_ETH_STATS,
    /* Get or set MTU */
    TEETH_MT_ETH_MTU,
};

/* base header */
struct teeth_base_hdr {
    uint32_t version: 4;        // TEETH_PROTOCOL_VERSION
    uint32_t msg_type: 4;
    uint32_t len : 16;           // length including headers
};

/*  echo response */
struct teeth_echo_hdr {
    struct teeth_base_hdr base;
    uint32_t reserved;
    uint64_t ts_utc_nano;       // time stamp affected by system clock adjustment
    uint64_t ts_mono_nano;      // time stamp not affected by system clock adjustment
};

#define TEETH_RX_FLAG_TX            0x00000001  // echo of a tx frame
#define TEETH_RX_FLAG_TRUNC         0x00000002  // frame was truncated
/* FCS (CRC) is present
 *
 * FCS is at the end of the frame and included in the length of the frame.
 * If present, the FCS has not been validated.
 */
#define TEETH_RX_FLAG_FCS_PRESENT   0x00000004

/* RX header
 *
 * Note there is no hardware time stamp field
 * as packet mmap must choose between hardware time stamps
 * (unsynced to host clock, which most nics don't support)
 * and software time stamps.
*/
struct teeth_eth_rx_hdr {
    struct teeth_base_hdr base;
    uint32_t flags;
    uint64_t ts_utc_nano;
};

#define TEETH_TX_FLAG_SUPPRESS_RESPONSE 0x0001

/* TX request header */
struct teeth_eth_tx_req_hdr {
    struct teeth_base_hdr base;
    uint32_t track_id : 16;
    uint32_t flags : 16;
};

#define TEETH_TX_ERROR_NONE         0 /* no error occurred */
#define TEETH_TX_ERROR_TOO_BIG      1 /* frame to big for transmission */
#define TEETH_TX_ERROR_TOO_SMALL    2 /* frame to small for transmission */
#define TEETH_TX_ERROR_MALFORMED    3 /* frame is malformed */
#define TEETH_TX_ERROR_QUEUE_FULL   4 /* tx queue is full */

/* TX respponse header */
struct teeth_eth_tx_res_hdr {
    struct teeth_base_hdr base;
    uint32_t track_id : 16;
    uint32_t error : 16;
};

#define TEETH_STATS_DUPLEX_MODE_HALF    0x0
#define TEETH_STATS_DUPLEX_MODE_FULL    0x1
#define TEETH_STATS_DUPLEX_MODE_UNKNOWN 0x3

/* Ethernet stats header */
struct teeth_eth_stats_hdr {
    struct teeth_base_hdr base;
    uint32_t mtu                : 16;
    uint32_t flags              : 12;
    uint32_t link_detected      : 1; // carrier / link present?
    uint32_t auto_negotiation   : 1; // enabled / disabled
    uint32_t duplex             : 2;
    uint32_t speed_mbps;
    // ethtool stats
    uint32_t tx_packets;    // delta to pervious stats
    uint32_t rx_packets;    // delta to pervious stats
    uint32_t tx_errors;     // delta to pervious stats
    uint32_t rx_errors;     // delta to pervious stats
    uint32_t rx_missed;
};

#define TEETH_MTU_ERROR_NONE            0 /* no error occurred */
#define TEETH_MTU_ERROR_OUT_OF_RANGE    1 /* MTU is too big or too small */

/* Ethernet MTU header
 *
 * Send of MTU of 0 to query the current MTU.
 */
struct teeth_eth_mtu_hdr {
    struct teeth_base_hdr base;
    uint16_t mtu;
    uint16_t error;
};

union teeth_hdr {
    struct teeth_echo_hdr echo;
    struct teeth_eth_rx_hdr rx;
    struct teeth_eth_tx_req_hdr tx_req;
    struct teeth_eth_tx_res_hdr tx_res;
    struct teeth_eth_stats_hdr stats;
    struct teeth_eth_mtu_hdr mtu;
};




#ifdef __cplusplus
}
#endif

#endif // TEETH_H
