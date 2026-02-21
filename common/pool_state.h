/*
 * pool_state.h - POOL Protocol State Machine (Platform-Independent)
 *
 * Defines the session state machine transitions and packet validation
 * rules. This code uses only pool_proto.h types and pool_platform.h
 * abstractions, making it portable across all target platforms.
 */

#ifndef POOL_STATE_H
#define POOL_STATE_H

#include "pool_proto.h"

/* Packet type validity matrix per session state.
 * Returns 1 if the given packet type is valid in the given state. */
static inline int pool_state_valid_pkt(uint8_t state, uint8_t pkt_type)
{
    switch (state) {
    case POOL_STATE_IDLE:
        return pkt_type == POOL_PKT_INIT;
    case POOL_STATE_INIT_SENT:
        return pkt_type == POOL_PKT_CHALLENGE;
    case POOL_STATE_CHALLENGED:
        return pkt_type == POOL_PKT_RESPONSE ||
               pkt_type == POOL_PKT_ACK;
    case POOL_STATE_ESTABLISHED:
        return pkt_type == POOL_PKT_DATA      ||
               pkt_type == POOL_PKT_ACK       ||
               pkt_type == POOL_PKT_HEARTBEAT ||
               pkt_type == POOL_PKT_REKEY     ||
               pkt_type == POOL_PKT_CLOSE     ||
               pkt_type == POOL_PKT_CONFIG    ||
               pkt_type == POOL_PKT_ROLLBACK  ||
               pkt_type == POOL_PKT_DISCOVER  ||
               pkt_type == POOL_PKT_JOURNAL   ||
               pkt_type == POOL_PKT_INTEGRITY;
    case POOL_STATE_REKEYING:
        return pkt_type == POOL_PKT_REKEY ||
               pkt_type == POOL_PKT_ACK  ||
               pkt_type == POOL_PKT_CLOSE;
    case POOL_STATE_CLOSING:
        return pkt_type == POOL_PKT_CLOSE ||
               pkt_type == POOL_PKT_ACK;
    default:
        return 0;
    }
}

/* Next state after processing a valid packet in the current state. */
static inline uint8_t pool_state_transition(uint8_t state, uint8_t pkt_type)
{
    switch (state) {
    case POOL_STATE_IDLE:
        if (pkt_type == POOL_PKT_INIT)
            return POOL_STATE_INIT_SENT;
        break;
    case POOL_STATE_INIT_SENT:
        if (pkt_type == POOL_PKT_CHALLENGE)
            return POOL_STATE_CHALLENGED;
        break;
    case POOL_STATE_CHALLENGED:
        if (pkt_type == POOL_PKT_RESPONSE || pkt_type == POOL_PKT_ACK)
            return POOL_STATE_ESTABLISHED;
        break;
    case POOL_STATE_ESTABLISHED:
        if (pkt_type == POOL_PKT_REKEY)
            return POOL_STATE_REKEYING;
        if (pkt_type == POOL_PKT_CLOSE)
            return POOL_STATE_CLOSING;
        return POOL_STATE_ESTABLISHED;
    case POOL_STATE_REKEYING:
        if (pkt_type == POOL_PKT_ACK)
            return POOL_STATE_ESTABLISHED;
        if (pkt_type == POOL_PKT_CLOSE)
            return POOL_STATE_CLOSING;
        break;
    case POOL_STATE_CLOSING:
        break;
    }
    return state;
}

#endif /* POOL_STATE_H */
