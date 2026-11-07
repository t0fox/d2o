#ifndef D2K_PROTOCOL_H
#define D2K_PROTOCOL_H
/* One source for the control handshake, release CLI and health records. */
#define D2K_CTL_PROTO_VERSION 22u /* v22: TLS binding shape includes TCP timestamp compatibility */

/* TCP TLS plan contexts. These values extend the existing shape byte so a
   plan confirmed with TCP timestamps cannot be selected for a client without
   them (and vice versa). */
#define D2K_TCP_SHAPE_MODERN_NO_TS  8u
#define D2K_TCP_SHAPE_LEGACY_NO_TS  9u
#define D2K_TCP_SHAPE_ECH_NO_TS    10u
#define D2K_TCP_SHAPE_MODERN_TS    11u
#define D2K_TCP_SHAPE_LEGACY_TS    12u
#define D2K_TCP_SHAPE_ECH_TS       13u
#define D2K_TCP_SHAPE_MAX D2K_TCP_SHAPE_ECH_TS

#define D2K_TCP_PROFILE_UNKNOWN 0u
#define D2K_TCP_PROFILE_NO_TS   1u
#define D2K_TCP_PROFILE_TS      2u
#endif
