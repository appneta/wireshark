/* packet-ani-rpp.c
 * Routines for Responder Packet Protocol dissection
 * Copyright 2007-2014 AppNeta
 *
 * RTP Parsing copied from packet-rtp.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include "config.h"
#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/proto.h>
#include <epan/dissectors/packet-rtp.h>

#define UDP_PORT_ANI_RPP  3239
#define RTP_HEADER_LENGTH 12
#define NO_FLOW           0xffffffff

const guchar ANI_PAYLOAD_SIGNATURE[] = { 0xEC, 0xBD, 0x7F, 0x60, 0xFF };
const guchar ANI_REPLY_PAYLOAD_SIGNATURE[] = { 0xEC, 0xBD, 0x7F, 0x60, 0xFD };
const guchar ANI_LEGACY_PAYLOAD_SIGNATURE[] = { 0xEC, 0xBD, 0x7F, 0x60, 0x54 };
const guchar PATHTEST_PAYLOAD_SIGNATURE[] = { 0xEC, 0xBD, 0x7F, 0x60, 0xFE };

enum appneta_pkt_type {
    APPNETA_PACKET_TYPE_UNDEFINED,
    APPNETA_PACKET_TYPE_PATH,
    APPNETA_PACKET_TYPE_PATH_REPLY,
    APPNETA_PACKET_TYPE_LEGACY,
    APPNETA_PACKET_TYPE_PATHTEST,
};
typedef enum appneta_pkt_type appneta_pkt_type_t;

/*
 * Fields in the first octet of the RTP header.
 */

/* Version is the first 2 bits of the first octet*/
#define RTP_VERSION(octet)  ((octet) >> 6)

/* Padding is the third bit; No need to shift, because true is any value
other than 0! */
#define RTP_PADDING(octet)  ((octet) & 0x20)

/* Extension bit is the fourth bit */
#define RTP_EXTENSION(octet)  ((octet) & 0x10)

/* CSRC count is the last four bits */
#define RTP_CSRC_COUNT(octet)  ((octet) & 0xF)

/*
 * Fields in the second octet of the RTP header.
 */

/* Marker is the first bit of the second octet */
#define RTP_MARKER(octet)  ((octet) & 0x80)

/* Payload type is the last 7 bits */
#define RTP_PAYLOAD_TYPE(octet)  ((octet) & 0x7F)

extern void dissect_ip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree);
extern void proto_register_responder_ip(void);

/* IF PROTO exposes code to other dissectors, then it must be exported
   in a header file. If not, a header file is not needed at all. */
/* #include "packet-ani-rpp.h" */

/* Forward declaration we need below */
void proto_register_ani_rpp(void);
void proto_reg_handoff_ani_rpp(void);

/* handle for sub-protocols */
static dissector_handle_t ani_rpp_handle = NULL;
static dissector_handle_t ip_handle = NULL;
static dissector_handle_t payload_handle = NULL;

gint proto_appneta_responder = -1;

/* Initialize the protocol and registered fields */
static gint proto_ani_rpp = -1;
static guint global_udp_port_artnet = UDP_PORT_ANI_RPP;

/* Responder packet fields */
static gint hf_ani_rpp_next_header_type = -1;
static gint hf_ani_rpp_header_length = -1;
static gint hf_ani_rpp_pkt_id = -1;
static gint hf_ani_rpp_flow_num = -1;
static gint hf_ani_rpp_flow_port = -1;
static gint hf_ani_rpp_flow_port_first = -1;
static gint hf_ani_rpp_flow_port_last = -1;
static gint hf_ani_rpp_test_weight = -1;
static gint hf_ani_rpp_error_code = -1;
static gint hf_ani_rpp_response_status = -1;
static gint hf_ani_rpp_responder_version_major = -1;
static gint hf_ani_rpp_responder_version_minor = -1;
static gint hf_ani_rpp_responder_version_revision = -1;
static gint hf_ani_rpp_responder_version_build = -1;
static gint hf_ani_rpp_unknown_header = -1;
static gint hf_ani_rpp_burst_size = -1;
static gint hf_ani_rpp_packet_size = -1;
static gint hf_ani_rpp_command_type = -1;
static gint hf_ani_rpp_first_id = -1;
static gint hf_ani_rpp_outbound_arrival_bits = -1;
static gint hf_ani_burst_hold_time_us = -1;
static gint hf_ani_burst_process_time_us = -1;
static gint hf_ani_rpp_outbound_arrival_times = -1;
static gint hf_ani_rpp_lost_id = -1;
static gint hf_ani_rpp_sipport = -1;
static gint hf_ani_rpp_ta_id = -1;
static gint hf_ani_rpp_protocol = -1;
static gint hf_ani_rpp_cb_inbound_packetcount = -1;
static gint hf_ani_rpp_cb_inbound_interpacketgap = -1;
static gint hf_ani_rpp_cb_outbound_packetcount = -1;
static gint hf_ani_rpp_cb_outbound_interpacketgap = -1;
static gint hf_ani_rpp_cb_inbound_flags_csv_debug = -1;
static gint hf_ani_rpp_cb_resp_ratelimitcbrate = -1;
static gint hf_ani_rpp_cb_resp_minpacketcount = -1;
static gint hf_ani_rpp_cb_flags_resp_csv_debug = -1;
static gint hf_ani_rpp_inboundpacketcount = -1;
static gint hf_ani_rpp_inboundpacketsize = -1;
static gint hf_ani_rpp_h323port = -1;
static gint hf_ani_rpp_appliance_type = -1;
static gint hf_ani_rpp_custom_appliance_type = -1;
static gint hf_ani_rpp_command_flags = -1;
static gint hf_ani_rpp_command_flags_is_jumbo = -1;
static gint hf_ani_rpp_command_flags_is_super_jumbo = -1;
static gint hf_ani_rpp_command_flags_is_inbound = -1;
static gint hf_ani_rpp_cb_request_reserved1 = -1;
static gint hf_ani_rpp_cb_request_reserved2 = -1;
static gint hf_ani_rpp_cb_ready_reserved1 = -1;
static gint hf_ani_rpp_cb_ready_reserved2 = -1;
static gint hf_ani_rpp_ecb_request_padding = -1;
static gint hf_ani_rpp_ecb_request_flags = -1;
static gint hf_ani_rpp_ecb_request_flags_first_seq = -1;
static gint hf_ani_rpp_ecb_request_flags_last_seq = -1;
static gint hf_ani_rpp_ecb_request_ssn = -1;
static gint hf_ani_rpp_ecb_request_outbound_magnify = -1;
static gint hf_ani_rpp_ecb_request_outbound_duration = -1;
static gint hf_ani_rpp_ecb_request_outbound_gap = -1;
static gint hf_ani_rpp_ecb_request_inbound_magnify = -1;
static gint hf_ani_rpp_ecb_request_inbound_duration = -1;
static gint hf_ani_rpp_ecb_request_inbound_gap = -1;
static gint hf_ani_rpp_ecb_resp_padding = -1;
static gint hf_ani_rpp_ecb_resp_flags = -1;
static gint hf_ani_rpp_ecb_resp_flags_in = -1;
static gint hf_ani_rpp_ecb_resp_flags_out = -1;
static gint hf_ani_rpp_ecb_resp_flags_final = -1;
static gint hf_ani_rpp_ecb_resp_outbound_first_tx_ts = -1;
static gint hf_ani_rpp_ecb_resp_outbound_first_rx_ts = -1;
static gint hf_ani_rpp_ecb_resp_outbound_ll_rx = -1;
static gint hf_ani_rpp_ecb_resp_outbound_ll_rx_bytes = -1;
static gint hf_ani_rpp_ecb_resp_outbound_ll_us = -1;
static gint hf_ani_rpp_ecb_resp_outbound_total_rx = -1;
static gint hf_ani_rpp_ecb_resp_outbound_total_rx_bytes = -1;
static gint hf_ani_rpp_ecb_resp_outbound_total_us = -1;
static gint hf_ani_rpp_ecb_resp_inbound_first_tx_ts = -1;
static gint hf_ani_rpp_ecb_resp_inbound_first_rx_ts = -1;
static gint hf_ani_rpp_ecb_resp_inbound_ll_rx = -1;
static gint hf_ani_rpp_ecb_resp_inbound_ll_rx_bytes = -1;
static gint hf_ani_rpp_ecb_resp_inbound_ll_us = -1;
static gint hf_ani_rpp_ecb_resp_inbound_total_rx = -1;
static gint hf_ani_rpp_ecb_resp_inbound_total_rx_bytes = -1;
static gint hf_ani_rpp_ecb_resp_inbound_total_us = -1;
static gint hf_ani_rpp_pseudo_chksum = -1;
static gint hf_ani_rpp_payload = -1;
static gint hf_ani_rpp_signature_undefined = -1;
static gint hf_ani_rpp_signature_path = -1;
static gint hf_ani_rpp_signature_path_reply = -1;
static gint hf_ani_rpp_signature_legacy = -1;
static gint hf_ani_rpp_signature_pathtest = -1;
static gint hf_ani_rpp_signature_flags = -1;
static gint hf_ani_rpp_signature_flags_first = -1;
static gint hf_ani_rpp_signature_flags_last = -1;
static gint hf_ani_rpp_signature_flags_iht = -1;
static gint hf_ani_rpp_signature_flags_ext = -1;
static gint hf_ani_rpp_signature_iht = -1;
static gint hf_ani_rpp_signature_burst_len = -1;

/* RTP header fields                                 */
/* Assumptions about RTP: no padding, no extensions, */
/* and no CSRC identifiers (i.e. 12 bytes only)      */
static gint hf_rtp_version      = -1;
static gint hf_rtp_padding      = -1;
static gint hf_rtp_extension    = -1;
static gint hf_rtp_csrc_count   = -1;
static gint hf_rtp_marker       = -1;
static gint hf_rtp_payload_type = -1;
static gint hf_rtp_seq_nr       = -1;
static gint hf_rtp_ext_seq_nr   = -1;
static gint hf_rtp_timestamp    = -1;
static gint hf_rtp_ssrc         = -1;

/* Initialize the subtree pointers */
static gint ett_ani_rpp = -1;
static gint ett_ani_rtp = -1;
static gint ett_ani_seq = -1;
static gint ett_ani_custom = -1;
static gint ett_ani_request = -1;
static gint ett_ani_reply = -1;
static gint ett_ani_flow_create = -1;
static gint ett_ani_flow_response = -1;
static gint ett_ani_flow_close = -1;
static gint ett_ani_test_weight = -1;
static gint ett_ani_test_parameters = -1;
static gint ett_ani_flow_not_found = -1;
static gint ett_ani_burst_info = -1;
static gint ett_ani_responder_version = -1;
static gint ett_ani_outbound_arrival = -1;
static gint ett_ani_burst_hold_time = -1;
static gint ett_ani_outbound_arrival_times = -1;
static gint ett_ani_lost_pkts = -1;
static gint ett_ani_sipport = -1;
static gint ett_ani_protocol = -1;
static gint ett_ani_controlled_burst = -1;
static gint ett_ani_controlled_burst_response = -1;
static gint ett_ani_inboundpacketattr = -1;
static gint ett_ani_h323port = -1;
static gint ett_ani_appliance_type = -1;
static gint ett_ani_error = -1;
static gint ett_ani_controlled_burst_request = -1;
static gint ett_ani_controlled_burst_ready = -1;
static gint ett_ani_enhanced_controlled_burst_request = -1;
static gint ett_ani_enhanced_controlled_burst_response = -1;
static gint ett_ani_signature = -1;
static gint ett_ani_pseudo_cksum = -1;
static gint ett_ani_invalid = -1;

/* Setup protocol subtree array */
static gint *ett[] = {
        &ett_ani_rpp,
        &ett_ani_rtp,
        &ett_ani_seq,
        &ett_ani_custom,
        &ett_ani_reply,
        &ett_ani_flow_create,
        &ett_ani_flow_response,
        &ett_ani_flow_close,
        &ett_ani_test_weight,
        &ett_ani_test_parameters,
        &ett_ani_burst_info,
        &ett_ani_responder_version,
        &ett_ani_outbound_arrival,
        &ett_ani_burst_hold_time,
        &ett_ani_outbound_arrival_times,
        &ett_ani_lost_pkts,
        &ett_ani_sipport,
        &ett_ani_protocol,
        &ett_ani_controlled_burst,
        &ett_ani_controlled_burst_response,
        &ett_ani_inboundpacketattr,
        &ett_ani_h323port,
        &ett_ani_appliance_type,
        &ett_ani_error,
        &ett_ani_controlled_burst_request,
        &ett_ani_controlled_burst_ready,
        &ett_ani_enhanced_controlled_burst_request,
        &ett_ani_enhanced_controlled_burst_response,
        &ett_ani_signature,
        &ett_ani_pseudo_cksum,
        &ett_ani_invalid,
};

/*
 * an array of pointers to the subtree index and pointer values to the
 * structure below.  NULL means don't print
 */
static gint *hf_subtrees[] = {
        NULL,
        NULL,                                           /* HDR_LAST */
        &ett_ani_seq,                                   /* HDR_SEQUENCE */
        &ett_ani_custom,                                /* HDR_CUSTOM_TYPE */
        &ett_ani_request,                               /* HDR_REQUEST */
        &ett_ani_reply,                                 /* HDR_REPLY */
        &ett_ani_flow_create,                            /* HDR_FLOW_CREATE */
        &ett_ani_flow_response,                          /* HDR_FLOW_RESPONSE */
        &ett_ani_flow_close,                             /* HDR_FLOW_CLOSE */
        &ett_ani_test_weight,                           /* HDR_TEST_WEIGHT */
        &ett_ani_test_parameters,                       /* HDR_TEST_PARAMS */
        &ett_ani_flow_not_found,                         /* HDR_FLOW_PACKET */
        &ett_ani_burst_info,                            /* HDR_COMMAND_INFO */
        &ett_ani_responder_version,                     /* HDR_RESPONDERVERSION */
        &ett_ani_outbound_arrival,                      /* HDR_OUTBOUNDARRIVAL */
        &ett_ani_burst_hold_time,                       /* HDR_RESPONDERHOLDTIME */
        &ett_ani_outbound_arrival_times,                /* HDR_OUTBOUNDARRIVALTIME */
        &ett_ani_lost_pkts,                             /* HDR_LOST_PACKETS */
        &ett_ani_sipport,                               /* HDR_SIPPORT */
        &ett_ani_protocol,                              /* HDR_PROTOCOL */
        &ett_ani_controlled_burst,                      /* HDR_CONTROLLEDBURST */
        &ett_ani_controlled_burst_response,             /* HDR_CONTROLLEDBURSTRESPONSE */
        &ett_ani_inboundpacketattr,                     /* HDR_INBOUNDPACKETATTR */
        &ett_ani_h323port,                              /* HDR_H323PORT */
        &ett_ani_appliance_type,                        /* HDR_APPLIANCE_TYPE */
        &ett_ani_error,                                 /* HDR_ERROR */
        &ett_ani_controlled_burst_request,              /* HDR_CONTROLLEDBURSTREQUEST */
        &ett_ani_controlled_burst_ready,                /* HDR_CONTROLLEDBURSTREADY */
        &ett_ani_enhanced_controlled_burst_request,     /* HDR_ECBREQUEST */
        &ett_ani_enhanced_controlled_burst_response,    /* HDR_ECBRESPONSE */
        &ett_ani_signature,                             /* HDR_SIGNATURE */
        &ett_ani_pseudo_cksum,                          /* HDR_PSEUDO_CKSUM */
        &ett_ani_invalid,                               /* HDR_RESERVED1 */
        &ett_ani_invalid,                               /* HDR_RESERVED2 */
        &ett_ani_invalid,                               /* HDR_RESERVED3 */
        &ett_ani_invalid,                               /* HDR_RESERVED4 */
        &ett_ani_invalid,                               /* HDR_RESERVED5 */
        &ett_ani_invalid,                               /* HDR_RESERVED6 */
        &ett_ani_invalid,                               /* HDR_RESERVED7 */
        &ett_ani_invalid,                               /* HDR_RESERVED8 */
        &ett_ani_invalid,                               /* HDR_RESERVED9 */
        &ett_ani_invalid,                               /* HDR_INVALID */
        NULL,
        NULL,
};

/*
 * descriptions corresponding to the above subree
 */
static const value_string ani_rpp_header_type_vals[] =
{
        { 1, "No more headers" },
        { 2, "Sequence" },
        { 3, "Custom Type" },
        { 4, "Request" },
        { 5, "Reply" },
        { 6, "Create Flow" },
        { 7, "Flow Response" },
        { 8, "Close Flow" },
        { 9, "Test Weight" },
        { 10, "Test Parameters" },
        { 11, "Flow not found" },
        { 12, "Command Info" },
        { 13, "Responder Version" },
        { 14, "Outbound Arrival Bits" },
        { 15, "Responder Hold Time" },
        { 16, "Outbound Arrival Times" },
        { 17, "Lost Packets" },
        { 18, "Sip Port" },
        { 19, "Protocol" },
        { 20, "Controlled Burst" },
        { 21, "Controlled Burst Response" },
        { 22, "Inbound Packet Attributes" },
        { 23, "H.323" },
        { 24, "Device Type" },
        { 25, "Error" },
        { 26, "Controlled Burst Request" },
        { 27, "Controlled Burst Ready" },
        { 28, "Enhanced Controlled Burst" },
        { 29, "Enhanced Controlled Burst Response" },
        { 30, "Signature Header" },
        { 31, "Pseudo Checksum" },
        { 32, "Reserved 1" },
        { 33, "Reserved 2" },
        { 34, "Reserved 3" },
        { 35, "Reserved 4" },
        { 36, "Reserved 5" },
        { 37, "Reserved 6" },
        { 38, "Reserved 7" },
        { 39, "Reserved 8" },
        { 40, "Reserved 9" },
        { 41, "Invalid Header" },
        { 0, NULL },
};

enum ResponderHeaderType
{
    HDR_LAST = 1,
    HDR_SEQUENCE,
    HDR_CUSTOM_TYPE,
    HDR_REQUEST,
    HDR_REPLY,              /* 5 */
    HDR_FLOW_CREATE,
    HDR_FLOW_RESPONSE,
    HDR_FLOW_CLOSE,
    HDR_TEST_WEIGHT,
    HDR_TEST_PARAMS,        /*10 */
    HDR_FLOW_PACKET, /* not actually a header, used to report flow not found */
    HDR_COMMAND_INFO,
    HDR_RESPONDERVERSION,
    HDR_OUTBOUNDARRIVAL,
    HDR_RESPONDERHOLDTIME,  /* 15 */
    HDR_OUTBOUNDARRIVALTIME,
    HDR_LOST_PACKETS,
    HDR_SIPPORT,
    HDR_PROTOCOL,
    HDR_CONTROLLEDBURST,    /* 20 */
    HDR_CONTROLLEDBURSTRESPONSE,
    HDR_INBOUNDPACKETATTR,
    HDR_H323PORT,
    HDR_APPLIANCE_TYPE,
    HDR_ERROR,             /* 25 */
    HDR_CONTROLLEDBURSTREQUEST,
    HDR_CONTROLLEDBURSTREADY,
    HDR_ECBREQUEST,
    HDR_ECBRESPONSE,
    HDR_SIGNATURE,         /* 30 */
    HDR_PSEUDO_CKSUM,
    HDR_RESERVED1,
    HDR_RESERVED2,
    HDR_RESERVED3,
    HDR_RESERVED4,
    HDR_RESERVED5,
    HDR_RESERVED6,
    HDR_RESERVED7,
    HDR_RESERVED8,
    HDR_RESERVED9,
    HDR_INVALID,
    HDR_COUNT,
} ResponderHeaderType;

/* strings to make protocol parsing more readable */
static const value_string rtp_version_vals[] =
{
        { 0, "Old VAT Version" },
        { 1, "First Draft Version" },
        { 2, "RFC 1889 Version" },
        { 0, NULL },
};


static const value_string ani_rpp_error_code_vals[] =
{
        { 0, "Success" },
        { 1, "QoS disabled" },
        { 2, "Unknown header" },
        { 3, "Option not supported" },
        { 4, "Administratively Prohibited" },
        { 5, "Must set DF" },
        { 6, "UDP checksum not supported" },
        { 7, "Internal error" },
        { 8, "Unknown flow" },
        { 9, "Count error" },
        { 10, "QoS lock unavailable" },
        { 11, "SIP port unavailable" },
        { 12, "QoS altered" },
        { 0, NULL }
};

static const value_string ani_rpp_cmd_type_vals[] =
{
        { 0, "Invalid" },
        { 1, "Burst" },
        { 2, "Datagram" },
        { 3, "Controlled Burst" },
        { 4, "Tight Datagram" },
        { 5, "Burst Load" },
        { 6, "Enhanced Controlled Burst" },
        { 0, "Invalid" },
        { 0x81, "Burst with Primer" },
        { 0x82, "Datagram with Primer" },
        { 0x83, "Controlled Burst with Primer" },
        { 0x84, "Tight Datagram with Primer" },
        { 0x85, "Burst Load with Primer" },
        { 0x86, "Controlled Burst with Primer" },
        { 0, NULL }
};

static const value_string ani_rpp_appliance_type_vals[] =
{
        { 0, "Invalid" },
        { 1, "Windows" },
        { 2, "Linux 32-bit" },
        { 3, "HP UX" },
        { 4, "Mac" },
        { 5, "iOS" },
        { 6, "Solaris Intel" },
        { 7, "Solaris SPARC" },
        { 8, "m20 appliance" },
        { 9, "m22 appliance" },
        { 10, "m30 appliance" },
        { 11, "r40 appliance" },
        { 12, "r400 appliance" },
        { 13, "virtual appliance" },
        { 14, "v30 appliance" },
        { 15, "Polycom HDX" },
        { 16, "Custom" },
        { 17, "Linux" },
        { 18, "m25 appliance" },
        { 19, "m35 appliance" },
        { 20, "r45 appliance" },
        { 21, "r450 appliance" },
        { 22, "vk35 appliance" },
        { 23, "vk25 appliance" },
        { 24, "wv00 appliance" },
        { 25, "Unknown" },
        { 26, "Unknown" },
        { 27, "Unknown" },
        { 28, "Unknown" },
        { 29, "Unknown" },
        { 30, "Unknown" },
        { 31, "Unknown" },
        { 32, "Unknown" },
        { 33, "Unknown" },
        { 0, NULL }
};

/*******************************************************************/
/* Parse the RTP header and return the number of bytes processed.
 * If ani_rpp_tree is set to NULL just return the length of
 * the header; otherwise add items to the dissector tree.
 */
static gint
dissect_rtp_header(tvbuff_t *tvb, packet_info *pinfo _U_, gint offset,
        proto_tree *ani_rpp_tree, gboolean *marker_set)
{
    guint8        octet1, octet2;
    guint16       seq_num;
    guint32       timestamp;
    guint32       sync_src;
    proto_tree*   rtp_tree = NULL;

    *marker_set = 0;

    /* Get the fields in the first octet */
    octet1 = tvb_get_guint8(tvb, offset);
    octet2 = tvb_get_guint8(tvb, offset + 1);

    if (octet1 != 0x80 || (octet2 & 0x7F) != 0x02) {
        /* this is not an RTP header, so return 0 bytes processed */
        return 0;
    }

    if (ani_rpp_tree == NULL) {
        /* just return the length without adding items to the dissector tree */
        return RTP_HEADER_LENGTH;
    }

    /* Get the fields in the second octet */
    *marker_set = RTP_MARKER( octet2);

    /* Get the subsequent fields */
    seq_num = tvb_get_ntohs( tvb, offset + 2);
    timestamp = tvb_get_ntohl( tvb, offset + 4);
    sync_src = tvb_get_ntohl( tvb, offset + 8);

    /* Create a subtree for RTP */
    if (sync_src == NO_FLOW) {
        rtp_tree = proto_tree_add_subtree_format(ani_rpp_tree, tvb, offset, RTP_HEADER_LENGTH, ett_ani_rtp, NULL,
                "Responder RTP Header: No flow, %s", *marker_set ? "Dual-ended" : "Single-ended");
    } else {
        rtp_tree = proto_tree_add_subtree_format(ani_rpp_tree, tvb, offset, RTP_HEADER_LENGTH, ett_ani_rtp, NULL,
                "Responder RTP Header: Flow %u, %s", sync_src, *marker_set ? "Dual-ended" : "Single-ended");
    }

    /* Add items to the RTP subtree */
    proto_tree_add_uint( rtp_tree, hf_rtp_version, tvb, offset, 1, octet1);
    proto_tree_add_boolean(rtp_tree, hf_rtp_padding, tvb, offset, 1, octet1);
    proto_tree_add_boolean(rtp_tree, hf_rtp_extension, tvb, offset, 1, octet1);
    proto_tree_add_uint( rtp_tree, hf_rtp_csrc_count, tvb, offset, 1, octet1);
    offset++;

    proto_tree_add_boolean(rtp_tree, hf_rtp_marker, tvb, offset,
            1, octet2);
    offset++;

    /* Sequence number 16 bits (2 octets) */
    proto_tree_add_uint( rtp_tree, hf_rtp_seq_nr, tvb, offset, 2, seq_num);
    offset += 2;

    /* Timestamp 32 bits (4 octets) */
    proto_tree_add_uint( rtp_tree, hf_rtp_timestamp, tvb, offset, 4, timestamp);
    offset += 4;

    /* Synchronization source identifier 32 bits (4 octets) */
    proto_tree_add_uint( rtp_tree, hf_rtp_ssrc, tvb, offset, 4, sync_src);
    offset += 4;

    return offset;
}

static proto_tree *add_subtree(tvbuff_t *tvb, gint *offset, proto_tree *current_tree,
        gint header, guint8 headerLength, const char *title)
{
    proto_tree *tree = NULL;

    if (current_tree && header < HDR_COUNT && hf_subtrees[header]) {
        tree = proto_tree_add_subtree(current_tree, tvb, *offset, headerLength,
                *(hf_subtrees[header]), NULL, title);
    }

    if (tree) {
        proto_tree_add_item(tree, hf_ani_rpp_next_header_type, tvb, *offset, 1, FALSE);
        proto_tree_add_item(tree, hf_ani_rpp_header_length, tvb, *offset+1, 1, FALSE);
    }

    *offset += 2;

    return tree;
}

/*******************************************************************/
/* Parse the responder header starting at the offset in the tvb
 * buffer.  If ani_rpp_tree is set to NULL just return the length of
 * the header; otherwise add items to the dissector tree.
 */
static gint
dissect_responder_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *ani_rpp_tree, void *data)
{
    gint currentHeader, nextHeader;
    guint8 headerLength = 0, mode = 0;
    guint8 flags = 0;
    gint offset = 0;
    guint32 id, flow, major, minor, revision, build, first_id = 0,
            burst_hold_time, i, depth;
    guint32 cb_in_count = 0,
            cb_in_gap = 0,
            cb_out_count = 0,
            cb_out_gap = 0,
            cb_in_flags = 0;
    guint16 port, portend, weight, burstsize = 0;
    proto_tree   *current_tree = NULL, *field_tree = NULL;
    proto_item  *tf = NULL;
    tvbuff_t *next_tvb;
    gboolean   save_in_error_pkt;
    gint remaining = tvb_captured_length_remaining(tvb, 0);
    guint pass = 0;

    if (data && strcmp(data, "payload") == 0)
        currentHeader = HDR_SIGNATURE;
    else
        currentHeader = HDR_SEQUENCE;
    while (currentHeader != HDR_LAST && currentHeader < HDR_INVALID) {
        current_tree = ani_rpp_tree;
        nextHeader = tvb_get_guint8(tvb, offset);
        headerLength = tvb_get_guint8(tvb, offset+1);

        if (offset > remaining || pass++ > 50) {
            g_print("dissect_responder_header: opps: offset=%d remaining=%d pass=%d\n",
                    offset, remaining, pass);
            return -1;
        }

        switch (currentHeader)
        {
        case HDR_SEQUENCE:
            current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
                    "Sequence Header");
            if (current_tree) {
                id = tvb_get_ntohl( tvb, offset);
                proto_tree_add_item(current_tree, hf_ani_rpp_pkt_id, tvb, offset, 4, FALSE);

                /* set some text in the info column */
                col_add_fstr(pinfo->cinfo, COL_INFO, "Responder: ID %d(0x%x)", id, id);
            }
            offset += (headerLength - 2);
            break;
        case HDR_ERROR:
            current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
                    "Error Header");
            if (current_tree) {
                proto_tree_add_item(current_tree, hf_ani_rpp_error_code, tvb, offset, 1, FALSE);
                proto_tree_add_item(current_tree, hf_ani_rpp_next_header_type, tvb, offset+1, 1, FALSE);

                /* set some text in the info column */
                col_append_str(pinfo->cinfo, COL_INFO, " [Contains Errors]");
            }
            offset += (headerLength - 2);
            break;
        case HDR_REQUEST:
            current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
                    "Request Header");
            offset += (headerLength - 2);
            break;
        case HDR_REPLY:
            current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
                    "Reply Header");
            /* the next 28 bytes are the ip and udp headers to be used in the response */
            if (current_tree) {
                /* Save the current value of the "we're inside an error packet"
                     flag, and set that flag; subdissectors may treat packets
                     that are the payload of error packets differently from
                     "real" packets. */
                save_in_error_pkt = pinfo->flags.in_error_pkt;
                pinfo->flags.in_error_pkt = TRUE;

                next_tvb = tvb_new_subset_remaining(tvb, offset);
                set_actual_length(next_tvb, 28);
                if (ip_handle) {
                    call_dissector( ip_handle, next_tvb, pinfo, current_tree);
                }

                /* Restore the "we're inside an error packet" flag. */
                pinfo->flags.in_error_pkt = save_in_error_pkt;

                /* set some text in the info column */
                col_append_str(pinfo->cinfo, COL_INFO, " Reply");
            }
            offset += (headerLength - 2);
            break;
        case HDR_FLOW_CREATE:
            current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
                    "Create Flow Header");
            if (current_tree) {
                port = tvb_get_ntohs( tvb, offset);
                if (headerLength >= 6) {
                    proto_tree_add_item(current_tree, hf_ani_rpp_flow_port_first, tvb, offset, 2, FALSE);
                    proto_tree_add_item(current_tree, hf_ani_rpp_flow_port_last, tvb, offset+2, 2, FALSE);
                } else {
                    proto_tree_add_item(current_tree, hf_ani_rpp_flow_port, tvb, offset, 2, FALSE);
                }

                /* set some text in the info column */
                if (headerLength >= 6) {
                    portend = tvb_get_ntohs( tvb, offset+2);
                    col_append_fstr(pinfo->cinfo, COL_INFO, " Create Flows (ports %d through %d)", port, portend);
                } else {
                    col_append_fstr(pinfo->cinfo, COL_INFO, " Create Flow (port %d)", port);
                }
            }
            offset += (headerLength - 2);
            break;
        case HDR_FLOW_RESPONSE:
            current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
                    "Reply Header");
            if (current_tree) {
                flow = tvb_get_ntohl( tvb, offset);
                port = tvb_get_ntohs( tvb, offset+4);
                proto_tree_add_item(current_tree, hf_ani_rpp_flow_num, tvb, offset, 4, FALSE);
                proto_tree_add_item(current_tree, hf_ani_rpp_flow_port, tvb, offset+4, 2, FALSE);
                proto_tree_add_item(current_tree, hf_ani_rpp_response_status, tvb, offset+6, 2, FALSE);

                /* tell Wireshark to dissect packets addressed to hf_ani_rpp_flow_port
                 * using this dissector.
                 */
                if (port != UDP_PORT_ANI_RPP)
                    dissector_add_uint("udp.port", port, ani_rpp_handle);

                /* set some text in the info column */
                col_append_fstr(pinfo->cinfo, COL_INFO, " Flow Response (flow ID %d)", flow);
            }
            offset += (headerLength - 2);
            break;
        case HDR_FLOW_CLOSE:
            current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
                    "Close Flow Header");
            if (current_tree) {
                flow = tvb_get_ntohl( tvb, offset);
                proto_tree_add_item(current_tree, hf_ani_rpp_flow_num, tvb, offset, 4, FALSE);
                proto_tree_add_item(current_tree, hf_ani_rpp_flow_port, tvb, offset+4, 2, FALSE);
                proto_tree_add_item(current_tree, hf_ani_rpp_response_status, tvb, offset+6, 2, FALSE);

                /* set some text in the info column */
                col_append_fstr(pinfo->cinfo, COL_INFO, " Close Flow (flow ID %d)", flow);
            }
            offset += (headerLength - 2);
            break;
        case HDR_TEST_WEIGHT:
            current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
                    "Test Weight Header");
            if (current_tree) {
                weight = tvb_get_ntohs( tvb, offset);
                proto_tree_add_item(current_tree, hf_ani_rpp_test_weight, tvb, offset, 2, FALSE);

                /* set some text in the info column */
                col_append_fstr(pinfo->cinfo, COL_INFO, " (weight %d)", weight);
            }
            offset += (headerLength - 2);
            break;
        case HDR_RESPONDERVERSION:
            current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
                    "Responder Version Header");
            if (current_tree) {
                major = tvb_get_ntohl( tvb, offset);
                minor = tvb_get_ntohl( tvb, offset+4);
                revision = tvb_get_ntohl( tvb, offset+8);
                build = tvb_get_ntohl( tvb, offset+12);
                proto_tree_add_item(current_tree, hf_ani_rpp_responder_version_major, tvb, offset, 4, FALSE);
                proto_tree_add_item(current_tree, hf_ani_rpp_responder_version_minor, tvb, offset+4, 4, FALSE);
                proto_tree_add_item(current_tree, hf_ani_rpp_responder_version_revision, tvb, offset+8, 4, FALSE);
                proto_tree_add_item(current_tree, hf_ani_rpp_responder_version_build, tvb, offset+12, 4, FALSE);

                /* set some text in the info column */
                col_append_fstr(pinfo->cinfo, COL_INFO, ", version %d.%d.%d.%d", major, minor, revision, build);
            }
            offset += (headerLength - 2);
            break;
        case HDR_COMMAND_INFO:
            current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
                    "Command Info Header");
            if (current_tree) {
                first_id = tvb_get_ntohl( tvb, offset);
                burstsize = tvb_get_ntohs( tvb, offset+4);
                proto_tree_add_item(current_tree, hf_ani_rpp_first_id, tvb, offset, 4, FALSE);
                proto_tree_add_item(current_tree, hf_ani_rpp_burst_size, tvb, offset+4, 2, FALSE);
                if (headerLength > 8) {
                    proto_tree_add_item(current_tree, hf_ani_rpp_packet_size, tvb, offset+6, 2, FALSE);
                }
                if (headerLength >= 11) {
                    proto_tree_add_item(current_tree, hf_ani_rpp_command_type, tvb, offset+8, 1, FALSE);
                    mode = tvb_get_guint8(tvb, offset+8);
                }
                if (headerLength >= 12) {
                    flags = tvb_get_guint8(tvb, offset + 9);
                    tf = proto_tree_add_uint(current_tree, hf_ani_rpp_command_flags, tvb, offset+9, 1, flags);
                    field_tree = proto_item_add_subtree( tf, ett_ani_burst_info);
                    proto_tree_add_boolean(field_tree, hf_ani_rpp_command_flags_is_jumbo, tvb, offset+9, 1, flags);
                    proto_tree_add_boolean(field_tree, hf_ani_rpp_command_flags_is_super_jumbo, tvb, offset+9, 1, flags);
                    proto_tree_add_boolean(field_tree, hf_ani_rpp_command_flags_is_inbound, tvb, offset+9, 1, flags);
                }

                /* set some text in the info column */
                if (mode == 1) {
                    col_append_fstr(pinfo->cinfo, COL_INFO, ", Burst");
                } else if (mode == 2) {
                    col_append_fstr(pinfo->cinfo, COL_INFO, ", Datagram");
                } else if (mode == 3) {
                    if ((flags & 0x4)) {
                        col_append_fstr(pinfo->cinfo, COL_INFO, ", Inbound Controlled Burst");
                    } else {
                        col_append_fstr(pinfo->cinfo, COL_INFO, ", Controlled Burst");
                    }
                } else if (mode == 4) {
                    col_append_fstr(pinfo->cinfo, COL_INFO, ", Tight Dgrm");
                } else if (mode == 5) {
                    col_append_fstr(pinfo->cinfo, COL_INFO, ", Burst Load");
                } else if (mode == 0x81) {
                    col_append_fstr(pinfo->cinfo, COL_INFO, ", Burst (Primer)");
                } else if (mode == 0x82) {
                    col_append_fstr(pinfo->cinfo, COL_INFO, ", Datagram (Primer)");
                } else if (mode == 0x83) {
                    col_append_fstr(pinfo->cinfo, COL_INFO, ", Controlled Burst (Primer)");
                } else if (mode == 0x84) {
                    col_append_fstr(pinfo->cinfo, COL_INFO, ", Tight Dgrm (Primer)");
                } else if (mode == 0x85) {
                    col_append_fstr(pinfo->cinfo, COL_INFO, ", Burst Load (Primer)");
                }
                col_append_fstr(pinfo->cinfo, COL_INFO, ", First ID %d, Packets %d", first_id, burstsize);
            }
            offset += (headerLength - 2);
            break;
        case HDR_OUTBOUNDARRIVAL:
            current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
                    "Outbound Arrival Bits");
            if (current_tree) {
                proto_tree_add_item(current_tree, hf_ani_rpp_outbound_arrival_bits, tvb, offset, 8, FALSE);

                /* set some text in the info column */
                col_append_fstr(pinfo->cinfo, COL_INFO, ", Response");
            }
            offset += (headerLength - 2);
            break;
        case HDR_RESPONDERHOLDTIME:
            current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
                    "Responder Hold Times");
            if (current_tree) {
                burst_hold_time = tvb_get_ntohl( tvb, offset);
                proto_tree_add_item(current_tree, hf_ani_burst_hold_time_us, tvb, offset, 4, FALSE);

                /* set some text in the info column */
                col_append_fstr(pinfo->cinfo, COL_INFO, ", Hold %u us", burst_hold_time);
            }
            offset += (headerLength - 2);
            break;
        case HDR_OUTBOUNDARRIVALTIME:
            current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
                    "Outbound Arrival Timestamps");
            i = 0;
            if (current_tree) {
                depth = headerLength - 2;
                for (; i<depth; i+=4) {
                    proto_tree_add_item(current_tree, hf_ani_rpp_outbound_arrival_times, tvb, offset+i, 4, FALSE);
                }
            }
            offset += (headerLength - 2);
            break;
        case HDR_LOST_PACKETS:
            current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
                    "Lost Packets");
            if (current_tree) {
                depth = headerLength - 2;
                for (i=0; i<depth; i+=4) {
                    proto_tree_add_item(current_tree, hf_ani_rpp_lost_id, tvb, offset+i, 4, FALSE);
                }
                col_append_fstr(pinfo->cinfo, COL_INFO, ", Loss");
            }
            offset += (headerLength - 2);
            break;
        case HDR_SIPPORT:
            current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
                    "Sip Port");
            if (current_tree) {
                guint32 idLength = headerLength - 4;
                proto_tree_add_item(current_tree, hf_ani_rpp_sipport, tvb, offset, 2, FALSE);
                proto_tree_add_item(current_tree, hf_ani_rpp_ta_id, tvb, offset + 2, idLength, FALSE);
            }
            offset += (headerLength - 2);
            break;
        case HDR_PROTOCOL:
            current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
                    "Protocol");
            if (current_tree) {
                proto_tree_add_item(current_tree, hf_ani_rpp_protocol, tvb, offset, 4, FALSE);
            }
            offset += (headerLength - 2);
            break;
        case HDR_CONTROLLEDBURST:
            current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
                    "Controlled Burst");
            if (current_tree) {
                cb_in_count = tvb_get_ntohl( tvb, offset);
                cb_in_gap = tvb_get_ntohl( tvb, offset+4);
                cb_in_flags = cb_in_count & 0x80000000;
                proto_tree_add_boolean(current_tree, hf_ani_rpp_cb_inbound_flags_csv_debug, tvb, offset, 4, cb_in_flags);
                proto_tree_add_uint(current_tree, hf_ani_rpp_cb_inbound_packetcount, tvb, offset, 4, cb_in_count & 0x7fffffff);
                proto_tree_add_uint(current_tree, hf_ani_rpp_cb_inbound_interpacketgap, tvb, offset+4, 4, cb_in_gap);
                if (cb_in_flags) {
                    col_append_fstr(pinfo->cinfo, COL_INFO, ", Debug ");
                } else {
                    col_append_fstr(pinfo->cinfo, COL_INFO, ", ");
                }
                if (headerLength >= 18) {
                    cb_out_count = tvb_get_ntohl( tvb, offset+8);
                    cb_out_gap = tvb_get_ntohl( tvb, offset+12);
                    proto_tree_add_uint(current_tree, hf_ani_rpp_cb_outbound_packetcount, tvb, offset+8, 4, cb_out_count);
                    proto_tree_add_uint(current_tree, hf_ani_rpp_cb_outbound_interpacketgap, tvb, offset+12, 4, cb_out_gap);
                    col_append_fstr(pinfo->cinfo, COL_INFO, "Out=%d/%d In=%d/%d (pkts/gap)",
                            cb_out_count, cb_out_gap, cb_in_count & 0x7fffffff, cb_in_gap);
                } else {
                    col_append_fstr(pinfo->cinfo, COL_INFO, "%d/%d (pkts/gap)", cb_in_count & 0x7fffffff, cb_in_gap);
                }
            }
            offset += (headerLength - 2);
            break;
        case HDR_CONTROLLEDBURSTRESPONSE:
            current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
                    "Controlled Burst Response");
            if (current_tree) {
                proto_tree_add_item(current_tree, hf_ani_rpp_cb_resp_ratelimitcbrate, tvb, offset, 4, FALSE);
                proto_tree_add_item(current_tree, hf_ani_rpp_cb_resp_minpacketcount, tvb, offset+4, 4, FALSE);
            }
            offset += (headerLength - 2);
            break;
        case HDR_INBOUNDPACKETATTR:
            current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
                    "Inbound Packet Attributes");
            if (current_tree) {
                proto_tree_add_item(current_tree, hf_ani_rpp_inboundpacketcount, tvb, offset, 2, FALSE);
                proto_tree_add_item(current_tree, hf_ani_rpp_inboundpacketsize, tvb, offset+2, 2, FALSE);
                burstsize = tvb_get_ntohs( tvb, offset);
                col_append_fstr(pinfo->cinfo, COL_INFO, "/%d (out/in)", burstsize);
            }
            offset += (headerLength - 2);
            break;
        case HDR_H323PORT:
            current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
                    "H.323");
            if (current_tree) {
                proto_tree_add_item(current_tree, hf_ani_rpp_h323port, tvb, offset, 2, FALSE);
            }
            offset += (headerLength - 2);
            break;
        case HDR_APPLIANCE_TYPE:
            current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
                    "Device Type");
            if (current_tree) {
                proto_tree_add_item(current_tree, hf_ani_rpp_appliance_type, tvb, offset, 1, FALSE);
            }
            offset += (headerLength - 2);
            break;
        case HDR_CUSTOM_TYPE:
            current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
                    "Custom Type");
            if (current_tree) {
                proto_tree_add_item(current_tree, hf_ani_rpp_custom_appliance_type, tvb, offset, headerLength - 2, FALSE);
            }
            offset += (headerLength - 2);
            break;
        case HDR_CONTROLLEDBURSTREADY:
            current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
                    "Controlled Burst Ready");
            if (current_tree) {
                proto_tree_add_item(current_tree, hf_ani_rpp_cb_ready_reserved1, tvb, offset, 4, FALSE);
                proto_tree_add_item(current_tree, hf_ani_rpp_cb_ready_reserved2, tvb, offset+4, 4, FALSE);
            }
            offset += (headerLength - 2);
            break;
        case HDR_CONTROLLEDBURSTREQUEST:
            current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
                    "Controlled Burst Request");
            if (current_tree) {
                proto_tree_add_item(current_tree, hf_ani_rpp_cb_request_reserved1, tvb, offset, 4, FALSE);
                proto_tree_add_item(current_tree, hf_ani_rpp_cb_request_reserved2, tvb, offset+4, 4, FALSE);
            }
            offset += (headerLength - 2);
            break;
        case HDR_ECBREQUEST:
            current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
                    "Enhanced Controlled Burst Request");
            if (current_tree) {
                gboolean first_seq, last_seq;
                flags = tvb_get_guint8(tvb, offset + 1);
                first_seq = !!(flags & 0x01);
                last_seq = !!(flags & 0x02);
                proto_tree_add_item(current_tree, hf_ani_rpp_ecb_request_padding, tvb, offset, 1, FALSE);
                tf = proto_tree_add_uint(current_tree, hf_ani_rpp_ecb_request_flags, tvb, offset+1, 1, flags);
                field_tree = proto_item_add_subtree( tf, ett_ani_enhanced_controlled_burst_request);
                if (first_seq) {
                    proto_item_append_text(tf, " (First sequence)");
                    col_append_fstr(pinfo->cinfo, COL_INFO, ", First Seq");
                }
                if (last_seq) {
                    proto_item_append_text(tf, " (Last sequence)");
                    col_append_fstr(pinfo->cinfo, COL_INFO, ", Last Seq");
                }
                proto_tree_add_boolean(field_tree, hf_ani_rpp_ecb_request_flags_last_seq, tvb, offset+1, 1, flags);
                proto_tree_add_boolean(field_tree, hf_ani_rpp_ecb_request_flags_first_seq, tvb, offset+1, 1, flags);
                proto_tree_add_item(current_tree, hf_ani_rpp_ecb_request_ssn, tvb, offset+2, 4, FALSE);
                proto_tree_add_item(current_tree, hf_ani_rpp_ecb_request_outbound_magnify, tvb, offset+6, 2, FALSE);
                col_append_fstr(pinfo->cinfo, COL_INFO, ", ECB out[mag=%ums", tvb_get_ntohs(tvb, offset+6));
                proto_tree_add_item(current_tree, hf_ani_rpp_ecb_request_outbound_duration, tvb, offset+8, 2, FALSE);
                col_append_fstr(pinfo->cinfo, COL_INFO, " dur=%ums", tvb_get_ntohs(tvb, offset+8));
                proto_tree_add_item(current_tree, hf_ani_rpp_ecb_request_outbound_gap, tvb, offset+10, 2, FALSE);
                col_append_fstr(pinfo->cinfo, COL_INFO, " gap=%uus]", tvb_get_ntohs(tvb, offset+10));
                proto_tree_add_item(current_tree, hf_ani_rpp_ecb_request_inbound_magnify, tvb, offset+12, 2, FALSE);
                col_append_fstr(pinfo->cinfo, COL_INFO, " in[mag=%ums", tvb_get_ntohs(tvb, offset+12));
                proto_tree_add_item(current_tree, hf_ani_rpp_ecb_request_inbound_duration, tvb, offset+14, 2, FALSE);
                col_append_fstr(pinfo->cinfo, COL_INFO, " dur=%ums", tvb_get_ntohs(tvb, offset+14));
                proto_tree_add_item(current_tree, hf_ani_rpp_ecb_request_inbound_gap, tvb, offset+16, 2, FALSE);
                col_append_fstr(pinfo->cinfo, COL_INFO, " gap=%uus]", tvb_get_ntohs(tvb, offset+16));
            }
            offset += (headerLength - 2);
            break;
        case HDR_ECBRESPONSE:
            current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
                    "Enhanced Controlled Burst Response");
            if (current_tree) {
                gboolean out_avail, in_avail, final_results;
                flags = tvb_get_guint8(tvb, offset + 1);
                out_avail = !!(flags & 0x01);
                in_avail = !!(flags & 0x02);
                final_results = !!(flags & 0x04);
                proto_tree_add_item(current_tree, hf_ani_rpp_ecb_resp_padding, tvb, offset, 1, FALSE);
                tf = proto_tree_add_uint(current_tree, hf_ani_rpp_ecb_resp_flags, tvb, offset+1, 1, flags);
                field_tree = proto_item_add_subtree( tf, ett_ani_enhanced_controlled_burst_response);
                proto_tree_add_boolean(field_tree, hf_ani_rpp_ecb_resp_flags_final, tvb, offset+1, 1, flags);
                proto_tree_add_boolean(field_tree, hf_ani_rpp_ecb_resp_flags_in, tvb, offset+1, 1, flags);
                proto_tree_add_boolean(field_tree, hf_ani_rpp_ecb_resp_flags_out, tvb, offset+1, 1, flags);
                proto_tree_add_item(current_tree, hf_ani_rpp_ecb_resp_outbound_first_tx_ts, tvb, offset+2, 4, FALSE);
                proto_tree_add_item(current_tree, hf_ani_rpp_ecb_resp_outbound_first_rx_ts, tvb, offset+6, 4, FALSE);
                proto_tree_add_item(current_tree, hf_ani_rpp_ecb_resp_outbound_ll_rx, tvb, offset+10, 4, FALSE);
                proto_tree_add_item(current_tree, hf_ani_rpp_ecb_resp_outbound_ll_rx_bytes, tvb, offset+14, 8, FALSE);
                proto_tree_add_item(current_tree, hf_ani_rpp_ecb_resp_outbound_ll_us, tvb, offset+22, 4, FALSE);
                proto_tree_add_item(current_tree, hf_ani_rpp_ecb_resp_outbound_total_rx, tvb, offset+26, 4, FALSE);
                proto_tree_add_item(current_tree, hf_ani_rpp_ecb_resp_outbound_total_rx_bytes, tvb, offset+30, 8, FALSE);
                proto_tree_add_item(current_tree, hf_ani_rpp_ecb_resp_outbound_total_us, tvb, offset+38, 4, FALSE);
                if (final_results) {
                    proto_item_append_text(tf, " (Final results)");
                    col_append_fstr(pinfo->cinfo, COL_INFO, " Final");
                }
                if (out_avail) {
                    proto_item_append_text(tf, " (Out-bound results)");
                    col_append_fstr(pinfo->cinfo, COL_INFO, " RX-out[ll=%u", tvb_get_ntohl(tvb, offset+10));
                    col_append_fstr(pinfo->cinfo, COL_INFO, "/%uus", tvb_get_ntohl(tvb, offset+22) - tvb_get_ntohl(tvb, offset+6));
                    col_append_fstr(pinfo->cinfo, COL_INFO, " total=%u", tvb_get_ntohl(tvb, offset+26));
                    col_append_fstr(pinfo->cinfo, COL_INFO, "/%uus]", tvb_get_ntohl(tvb, offset+38) - tvb_get_ntohl(tvb, offset+6));
                }
                proto_tree_add_item(current_tree, hf_ani_rpp_ecb_resp_inbound_first_tx_ts, tvb, offset+42, 4, FALSE);
                proto_tree_add_item(current_tree, hf_ani_rpp_ecb_resp_inbound_first_rx_ts, tvb, offset+46, 4, FALSE);
                proto_tree_add_item(current_tree, hf_ani_rpp_ecb_resp_inbound_ll_rx, tvb, offset+50, 4, FALSE);
                proto_tree_add_item(current_tree, hf_ani_rpp_ecb_resp_inbound_ll_rx_bytes, tvb, offset+54, 8, FALSE);
                proto_tree_add_item(current_tree, hf_ani_rpp_ecb_resp_inbound_ll_us, tvb, offset+62, 4, FALSE);
                proto_tree_add_item(current_tree, hf_ani_rpp_ecb_resp_inbound_total_rx, tvb, offset+66, 4, FALSE);
                proto_tree_add_item(current_tree, hf_ani_rpp_ecb_resp_inbound_total_rx_bytes, tvb, offset+70, 8, FALSE);
                proto_tree_add_item(current_tree, hf_ani_rpp_ecb_resp_inbound_total_us, tvb, offset+78, 4, FALSE);
                if (in_avail) {
                    proto_item_append_text(tf, " (In-bound results)");
                    col_append_fstr(pinfo->cinfo, COL_INFO, " RX-in[ll=%u", tvb_get_ntohl(tvb, offset+50));
                    col_append_fstr(pinfo->cinfo, COL_INFO, "/%uus", tvb_get_ntohl(tvb, offset+62) - tvb_get_ntohl(tvb, offset+46));
                    col_append_fstr(pinfo->cinfo, COL_INFO, " total=%u", tvb_get_ntohl(tvb, offset+66));
                    col_append_fstr(pinfo->cinfo, COL_INFO, "/%uus]", tvb_get_ntohl(tvb, offset+78) - tvb_get_ntohl(tvb, offset+46));
                }
            }
            offset += (headerLength - 2);
            break;
        case HDR_SIGNATURE:
            current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
                    "Signature Header");
            if (current_tree) {
                const guint8 *cp = tvb_get_ptr(tvb, offset,
                        tvb_captured_length_remaining(tvb, offset));
                appneta_pkt_type_t pkt_type = APPNETA_PACKET_TYPE_UNDEFINED;

                if (cp) {
                    if (!memcmp(cp, ANI_PAYLOAD_SIGNATURE, sizeof(ANI_PAYLOAD_SIGNATURE)))
                        pkt_type = APPNETA_PACKET_TYPE_PATH;
                    else if (!memcmp(cp, ANI_REPLY_PAYLOAD_SIGNATURE, sizeof(ANI_REPLY_PAYLOAD_SIGNATURE)))
                        pkt_type = APPNETA_PACKET_TYPE_PATH_REPLY;
                    else if (!memcmp(cp, ANI_LEGACY_PAYLOAD_SIGNATURE, sizeof(ANI_LEGACY_PAYLOAD_SIGNATURE)))
                        pkt_type = APPNETA_PACKET_TYPE_LEGACY;
                    else if (!memcmp(cp, PATHTEST_PAYLOAD_SIGNATURE, sizeof(PATHTEST_PAYLOAD_SIGNATURE)))
                        pkt_type = APPNETA_PACKET_TYPE_PATHTEST;
                }

                if (headerLength > 6) {
                    /* this is a dual-ended signature */
                    switch (pkt_type) {
                    case APPNETA_PACKET_TYPE_PATH:
                        proto_tree_add_item(current_tree, hf_ani_rpp_signature_path, tvb, offset,
                                sizeof(ANI_PAYLOAD_SIGNATURE), ENC_NA);
                        break;
                    case APPNETA_PACKET_TYPE_PATH_REPLY:
                        proto_tree_add_item(current_tree, hf_ani_rpp_signature_path_reply, tvb, offset,
                                sizeof(ANI_REPLY_PAYLOAD_SIGNATURE), ENC_NA);
                        break;
                    case APPNETA_PACKET_TYPE_LEGACY:
                        proto_tree_add_item(current_tree, hf_ani_rpp_signature_legacy, tvb, offset,
                                sizeof(ANI_LEGACY_PAYLOAD_SIGNATURE), ENC_NA);
                        break;
                    case APPNETA_PACKET_TYPE_PATHTEST:
                        proto_tree_add_item(current_tree, hf_ani_rpp_signature_pathtest, tvb, offset,
                                sizeof(PATHTEST_PAYLOAD_SIGNATURE), ENC_NA);
                        break;
                    default:
                        proto_tree_add_item(current_tree, hf_ani_rpp_signature_undefined,
                                tvb, offset, sizeof(ANI_PAYLOAD_SIGNATURE), ENC_NA);
                    }

                    switch (pkt_type) {
                    case APPNETA_PACKET_TYPE_PATH:
                    case APPNETA_PACKET_TYPE_PATH_REPLY:
                        flags = tvb_get_guint8(tvb, offset + 5);
                        tf = proto_tree_add_uint(current_tree, hf_ani_rpp_signature_flags, tvb, offset+5, 1, flags);
                        field_tree = proto_item_add_subtree( tf, ett_ani_signature);
                        proto_tree_add_boolean(field_tree, hf_ani_rpp_signature_flags_ext, tvb, offset+5, 1, flags);
                        proto_tree_add_boolean(field_tree, hf_ani_rpp_signature_flags_iht, tvb, offset+5, 1, flags);
                        proto_tree_add_boolean(field_tree, hf_ani_rpp_signature_flags_last, tvb, offset+5, 1, flags);
                        proto_tree_add_boolean(field_tree, hf_ani_rpp_signature_flags_first, tvb, offset+5, 1, flags);
                        break;
                    default:
                        ;
                    }
                    proto_tree_add_item(current_tree, hf_ani_rpp_signature_burst_len, tvb, offset+6, 4, FALSE);
                    proto_tree_add_item(current_tree, hf_ani_rpp_signature_iht, tvb, offset+10, 4, FALSE);
                } else {
                    /* this is a single-ended or ICMP extended packet signature found in payload */
                    proto_tree_add_item(current_tree, hf_ani_rpp_signature_iht, tvb, offset, 4, FALSE);
                }

            }
            offset += (headerLength - 2);
            break;
        case HDR_PSEUDO_CKSUM:
                current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
                        "Pseudo Checksum");
                if (current_tree) {
                    tf = proto_tree_add_item(current_tree, hf_ani_rpp_pseudo_chksum, tvb, offset, 2, FALSE);
                    field_tree = proto_item_add_subtree( tf, ett_ani_pseudo_cksum);
                }
            offset += (headerLength - 2);
            break;
        default:
            current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
                    "Unknown Header");
            if (current_tree) {
                tf = proto_tree_add_item(current_tree, hf_ani_rpp_unknown_header, tvb, offset, headerLength-2, FALSE);
                field_tree = proto_item_add_subtree( tf, ett_ani_invalid);

                /* set some text in the info column */
                col_append_str(pinfo->cinfo, COL_INFO, " [Unknown Header]");

            }
            offset += (headerLength - 2);
        }
        currentHeader = nextHeader;
    }

    return offset;
}

/*******************************************************************/
/* Code to actually dissect the packets
 */
static gint
dissect_ani_rpp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    unsigned int offset = 0;
    gboolean            marker_set;

    /* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "appneta_rpp");
    col_set_str(pinfo->cinfo, COL_INFO, "APPNETA_RPP Request");
    col_clear(pinfo->cinfo, COL_INFO);

    /* determine how many bytes of the packet will be processed */
    offset = dissect_rtp_header(tvb, pinfo, offset, NULL, &marker_set);

    if (tree) {
        proto_item *ti = NULL;
        proto_tree *ani_rpp_tree = NULL;

        /* Indicate the number of bytes that will be processed */
        ti = proto_tree_add_item(tree, proto_ani_rpp, tvb, 0, offset, FALSE);

        /* Get a pointer to our subtree */
        ani_rpp_tree = proto_item_add_subtree(ti, ett_ani_rpp);

        /* Add items to our subtree */
        offset = 0;
        offset = dissect_rtp_header (tvb, pinfo, offset, ani_rpp_tree, &marker_set);
        tvb = tvb_new_subset(tvb, offset, -1, -1);
        offset = dissect_responder_header(tvb, pinfo, ani_rpp_tree, data);
        col_append_fstr(pinfo->cinfo, COL_INFO, marker_set ? ", Dual-ended" : ", Single-ended");
        call_dissector(payload_handle, tvb_new_subset(tvb, offset, -1, -1), pinfo, tree);
    }

    /* Return the amount of data this dissector was able to dissect */
    return tvb_captured_length(tvb);
}

static const true_false_string ani_tf_set_not_set = {
    "Set",
    "Not Set"
};

/*******************************************************************/
/* Register the protocol with Wireshark
 */
void
proto_register_ani_rpp(void)
{
    module_t *ani_rpp_module;

    static hf_register_info hf[] = {

            {
                    &hf_rtp_version,
                    {
                            "RTP Version",
                            "rtp.version",
                            FT_UINT8,
                            BASE_DEC,
                            VALS(rtp_version_vals),
                            0xC0,
                            "", HFILL
                    }
            },
            {
                    &hf_rtp_padding,
                    {
                            "RTP Padding",
                            "rtp.padding",
                            FT_BOOLEAN,
                            8,
                            NULL,
                            0x20,
                            "", HFILL
                    }
            },
            {
                    &hf_rtp_extension,
                    {
                            "RTP Extension",
                            "rtp.ext",
                            FT_BOOLEAN,
                            8,
                            NULL,
                            0x10,
                            "", HFILL
                    }
            },
            {
                    &hf_rtp_csrc_count,
                    {
                            "RTP Contributing source identifiers count",
                            "rtp.cc",
                            FT_UINT8,
                            BASE_DEC,
                            NULL,
                            0x0F,
                            "", HFILL
                    }
            },
            {
                    &hf_rtp_marker,
                    {
                            "RTP Marker (Dual-ended)",
                            "rtp.marker",
                            FT_BOOLEAN,
                            8,
                            NULL,
                            0x80,
                            "", HFILL
                    }
            },
            {
                    &hf_rtp_payload_type,
                    {
                            "RTP Payload type",
                            "rtp.p_type",
                            FT_UINT8,
                            BASE_DEC,
                            NULL,
                            0x7F,
                            "", HFILL
                    }
            },
            {
                    &hf_rtp_seq_nr,
                    {
                            "RTP Sequence number",
                            "rtp.seq",
                            FT_UINT16,
                            BASE_DEC,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_rtp_ext_seq_nr,
                    {
                            "RTP Extended sequence number",
                            "rtp.extseq",
                            FT_UINT32,
                            BASE_DEC,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_rtp_timestamp,
                    {
                            "RTP Timestamp",
                            "rtp.timestamp",
                            FT_UINT32,
                            BASE_DEC,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_rtp_ssrc,
                    {
                            "RTP SSRC",
                            "rtp.ssrc",
                            FT_UINT32,
                            BASE_DEC,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_next_header_type,
                    {
                            "Next Header Type",
                            "appneta_rpp.next_hdr_type",
                            FT_UINT8,
                            BASE_DEC,
                            VALS(ani_rpp_header_type_vals),
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_header_length,
                    {
                            "Header Length",
                            "appneta_rpp.hdr_length",
                            FT_UINT8,
                            BASE_DEC,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_pkt_id,
                    {
                            "Packet ID",
                            "appneta_rpp.pkt_id",
                            FT_UINT32,
                            BASE_DEC,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_error_code,
                    {
                            "Error Code",
                            "appneta_rpp.err_code",
                            FT_UINT8,
                            BASE_DEC,
                            VALS(ani_rpp_error_code_vals),
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_response_status,
                    {
                            "Status",
                            "appneta_rpp.status",
                            FT_UINT16,
                            BASE_DEC,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_flow_num,
                    {
                            "Flow Number",
                            "appneta_rpp.flow_num",
                            FT_UINT32,
                            BASE_DEC,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_flow_port,
                    {
                            "Flow Port",
                            "appneta_rpp.flow_port",
                            FT_UINT16,
                            BASE_DEC,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_flow_port_first,
                    {
                            "Flow Port First",
                            "appneta_rpp.flow_port_first",
                            FT_UINT16,
                            BASE_DEC,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_flow_port_last,
                    {
                            "Flow Port Last",
                            "appneta_rpp.flow_port_last",
                            FT_UINT16,
                            BASE_DEC,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_test_weight,
                    {
                            "Test Weight",
                            "appneta_rpp.test_weight",
                            FT_UINT16,
                            BASE_DEC,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_responder_version_major,
                    {
                            "Major",
                            "appneta_rpp.responder_version_major",
                            FT_UINT16,
                            BASE_DEC,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_responder_version_minor,
                    {
                            "Minor",
                            "appneta_rpp.responder_version_minor",
                            FT_UINT16,
                            BASE_DEC,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_responder_version_revision,
                    {
                            "Revision",
                            "appneta_rpp.responder_version_revision",
                            FT_UINT16,
                            BASE_DEC,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_responder_version_build,
                    {
                            "Build",
                            "appneta_rpp.responder_version_build",
                            FT_UINT16,
                            BASE_DEC,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_burst_size,
                    {
                            "Packets",
                            "appneta_rpp.burst_size",
                            FT_UINT16,
                            BASE_DEC,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_packet_size,
                    {
                            "Packet Size",
                            "appneta_rpp.packet_size",
                            FT_UINT16,
                            BASE_DEC,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_command_type,
                    {
                            "Command Type",
                            "appneta_rpp.command_type",
                            FT_UINT8,
                            BASE_HEX,
                            VALS(ani_rpp_cmd_type_vals),
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_first_id,
                    {
                            "First Packet ID in Command",
                            "appneta_rpp.first_id",
                            FT_UINT32,
                            BASE_DEC_HEX,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_outbound_arrival_bits,
                    {
                            "Outbound Arrival Bits",
                            "appneta_rpp.outbound_bits",
                            FT_UINT64,
                            BASE_HEX,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_burst_hold_time_us,
                    {
                            "Responder hold time usec",
                            "appneta_rpp.burst_hold_time",
                            FT_UINT32,
                            BASE_DEC,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_cb_flags_resp_csv_debug,
                    {
                            "Responder CSV Debug",
                            "appneta_rpp.resp_csv_debug",
                            FT_UINT32,
                            BASE_DEC,
                            NULL,
                            0x80000000,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_command_flags,
                    {
                            "Command Flags",
                            "appneta_rpp.command_flags",
                            FT_UINT8,
                            BASE_HEX,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_command_flags_is_jumbo,
                    {
                            "Is Jumbo Packet",
                            "appneta_rpp.is_jumbo",
                            FT_BOOLEAN,
                            8,
                            NULL,
                            0x01,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_command_flags_is_super_jumbo,
                    {
                            "Is Super Jumbo Packet",
                            "appneta_rpp.is_super_jumbo",
                            FT_BOOLEAN,
                            8,
                            NULL,
                            0x02,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_command_flags_is_inbound,
                    {
                            "Is Inbound Packet",
                            "appneta_rpp.is_inbound",
                            FT_BOOLEAN,
                            8,
                            NULL,
                            0x04,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_burst_process_time_us,
                    {
                            "Responder processing time usec",
                            "appneta_rpp.burst_proc_time",
                            FT_UINT32,
                            BASE_DEC,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_outbound_arrival_times,
                    {
                            "Outbound Arrival Times",
                            "appneta_rpp.outbound_times",
                            FT_UINT32,
                            BASE_DEC,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_lost_id,
                    {
                            "Lost Packet ID",
                            "appneta_rpp.lost_id",
                            FT_UINT32,
                            BASE_DEC_HEX,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_sipport,
                    {
                            "Sip Port",
                            "appneta_rpp.sip_port",
                            FT_UINT16,
                            BASE_DEC,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_ta_id,
                    {
                            "Traffic Analysys ID",
                            "appneta_rpp.ta_id",
                            FT_STRING,
                            BASE_NONE,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_protocol,
                    {
                            "Sequencer Protocol Version",
                            "appneta_rpp.protocol",
                            FT_UINT32,
                            BASE_DEC,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_cb_inbound_packetcount,
                    {
                            "Inbound Packet Count",
                            "appneta_rpp.cb_inbound_packet_count",
                            FT_UINT32,
                            BASE_DEC,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_cb_inbound_interpacketgap,
                    {
                            "Inbound Inter-packet Gap (usec)",
                            "appneta_rpp.cb_inbound_interpacket_gap",
                            FT_UINT32,
                            BASE_DEC,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_cb_outbound_packetcount,
                    {
                            "Outbound Packet Count",
                            "appneta_rpp.cb_outbound_packet_count",
                            FT_UINT32,
                            BASE_DEC,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_cb_outbound_interpacketgap,
                    {
                            "Outbound Inter-packet Gap (usec)",
                            "appneta_rpp.cb_outbound_interpacket_gap",
                            FT_UINT32,
                            BASE_DEC,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_cb_inbound_flags_csv_debug,
                    {
                            "CSV Debug",
                            "appneta_rpp.cb_flags_is_csv_debug",
                            FT_BOOLEAN,
                            32,
                            NULL,
                            0x80000000,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_cb_resp_ratelimitcbrate,
                    {
                            "Rate Limit CB Rate",
                            "appneta_rpp.cb_resp_ratelimit_cb_rate",
                            FT_UINT32,
                            BASE_DEC,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_cb_resp_minpacketcount,
                    {
                            "Minimum Packet Count",
                            "appneta_rpp.cb_resp_min_packet_count",
                            FT_UINT32,
                            BASE_DEC,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_cb_request_reserved1,
                    {
                            "Rate Limit CB Request - reserved1",
                            "appneta_rpp.cb_resp_ratelimit_cb_request_reserved1",
                            FT_UINT32,
                            BASE_DEC,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_cb_request_reserved2,
                    {
                            "Rate Limit CB Request - reserved2",
                            "appneta_rpp.cb_resp_ratelimit_cb_request_reserved2",
                            FT_UINT32,
                            BASE_DEC,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_cb_ready_reserved1,
                    {
                            "Rate Limit CB Ready - reserved1",
                            "appneta_rpp.cb_resp_ratelimit_cb_ready_reserved1",
                            FT_UINT32,
                            BASE_DEC,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_cb_ready_reserved2,
                    {
                            "Rate Limit CB Ready - reserved2",
                            "appneta_rpp.cb_resp_ratelimit_cb_ready_reserved2",
                            FT_UINT32,
                            BASE_DEC,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_ecb_request_padding,
                    {
                            "ECB Request padding",
                            "appneta_rpp.ecb_request_padding",
                            FT_UINT8,
                            BASE_DEC,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_ecb_request_flags,
                    {
                            "ECB Request flags",
                            "appneta_rpp.ecb_request_flags",
                            FT_UINT8,
                            BASE_HEX,
                            NULL,
                            0x0,
                            NULL, HFILL
                    }
            },
            {
                    &hf_ani_rpp_ecb_request_flags_first_seq,
                    {
                            "First sequence",
                            "appneta_rpp.ecb_request_flags.first",
                            FT_BOOLEAN,
                            8,
                            TFS(&ani_tf_set_not_set),
                            0x01,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_ecb_request_flags_last_seq,
                    {
                            "Last sequence",
                            "appneta_rpp.ecb_request_flags.last",
                            FT_BOOLEAN,
                            8,
                            TFS(&ani_tf_set_not_set),
                            0x02,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_ecb_request_ssn,
                    {
                            "ECB Starting Sequence Number",
                            "appneta_rpp.ecb_request_ssn",
                            FT_UINT32,
                            BASE_DEC_HEX,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_ecb_request_outbound_magnify,
                    {
                            "ECB Out-bound Magnification",
                            "appneta_rpp.ecb_request_outbound_magnify",
                            FT_UINT16,
                            BASE_DEC,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_ecb_request_outbound_duration,
                    {
                            "ECB Out-bound Duration (msec)",
                            "appneta_rpp.ecb_request_outbound_duration",
                            FT_UINT16,
                            BASE_DEC,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_ecb_request_outbound_gap,
                    {
                            "ECB Out-bound Inter-packet Gap (usec)",
                            "appneta_rpp.ecb_request_outbound_gap",
                            FT_UINT16,
                            BASE_DEC,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_ecb_request_inbound_magnify,
                    {
                            "ECB In-bound Magnification",
                            "appneta_rpp.ecb_request_inbound_magnify",
                            FT_UINT16,
                            BASE_DEC,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_ecb_request_inbound_duration,
                    {
                            "ECB In-bound Duration (msec)",
                            "appneta_rpp.ecb_request_inbound_duration",
                            FT_UINT16,
                            BASE_DEC,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_ecb_request_inbound_gap,
                    {
                            "ECB In-bound Inter-packet Gap (usec)",
                            "appneta_rpp.ecb_request_inbound_gap",
                            FT_UINT16,
                            BASE_DEC,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_ecb_resp_padding,
                    {
                            "ECB Response padding",
                            "appneta_rpp.ecb_resp_padding",
                            FT_UINT8,
                            BASE_DEC,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_ecb_resp_flags,
                    {
                            "ECB Response flags",
                            "appneta_rpp.ecb_resp_flags",
                            FT_UINT8,
                            BASE_HEX,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_ecb_resp_flags_in,
                    {
                            "In-bound results available",
                            "appneta_rpp.ecb_resp_flags.in",
                            FT_BOOLEAN,
                            8,
                            TFS(&ani_tf_set_not_set),
                            0x02,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_ecb_resp_flags_out,
                    {
                            "Out-bound results available",
                            "appneta_rpp.ecb_resp_flags.out",
                            FT_BOOLEAN,
                            8,
                            TFS(&ani_tf_set_not_set),
                            0x01,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_ecb_resp_flags_final,
                    {
                            "Final results",
                            "appneta_rpp.ecb_resp_flags.final",
                            FT_BOOLEAN,
                            8,
                            TFS(&ani_tf_set_not_set),
                            0x04,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_ecb_resp_outbound_first_tx_ts,
                    {
                            "ECB Response Out-bound TX timstamp (usecs)",
                            "appneta_rpp.ecb_resp_outbound_first_tx_ts",
                            FT_UINT32,
                            BASE_DEC,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_ecb_resp_outbound_first_rx_ts,
                    {
                            "ECB Response Out-bound First RX timestamp (usecs)",
                            "appneta_rpp.ecb_resp_outbound_first_rx_ts",
                            FT_UINT32,
                            BASE_DEC,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_ecb_resp_outbound_ll_rx,
                    {
                            "ECB Response Out-bound loss-less RX (packets)",
                            "appneta_rpp.ecb_resp_outbound_ll_rx",
                            FT_UINT32,
                            BASE_DEC,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_ecb_resp_outbound_ll_rx_bytes,
                    {
                            "ECB Response Out-bound loss-less RX (bytes)",
                            "appneta_rpp.ecb_resp_outbound_ll_rx_bytes",
                            FT_UINT64,
                            BASE_DEC,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_ecb_resp_outbound_ll_us,
                    {
                            "ECB Response Out-bound loss-less RX timestamp (usec)",
                            "appneta_rpp.ecb_resp_outbound_ll_us",
                            FT_UINT32,
                            BASE_DEC,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_ecb_resp_outbound_total_rx,
                    {
                            "ECB Response Out-bound total RX (packets)",
                            "appneta_rpp.ecb_resp_outbound_total_rx",
                            FT_UINT32,
                            BASE_DEC,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_ecb_resp_outbound_total_rx_bytes,
                    {
                            "ECB Response Out-bound total RX (bytes)",
                            "appneta_rpp.ecb_resp_outbound_total_rx_bytes",
                            FT_UINT64,
                            BASE_DEC,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_ecb_resp_outbound_total_us,
                    {
                            "ECB Response Out-bound total RX timestamp (usec)",
                            "appneta_rpp.ecb_resp_outbound_total_us",
                            FT_UINT32,
                            BASE_DEC,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_ecb_resp_inbound_first_tx_ts,
                    {
                            "ECB Response In-bound TX timestamp (usecs)",
                            "appneta_rpp.ecb_resp_inbound_first_tx_ts",
                            FT_UINT32,
                            BASE_DEC,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_ecb_resp_inbound_first_rx_ts,
                    {
                            "ECB Response In-bound First RX timestamp (usecs)",
                            "appneta_rpp.ecb_resp_inbound_first_rx_ts",
                            FT_UINT32,
                            BASE_DEC,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_ecb_resp_inbound_ll_rx,
                    {
                            "ECB Response In-bound loss-less RX (packets)",
                            "appneta_rpp.ecb_resp_inbound_ll_rx",
                            FT_UINT32,
                            BASE_DEC,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_ecb_resp_inbound_ll_rx_bytes,
                    {
                            "ECB Response In-bound loss-less RX (bytes)",
                            "appneta_rpp.ecb_resp_inbound_ll_rx_bytes",
                            FT_UINT64,
                            BASE_DEC,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_ecb_resp_inbound_ll_us,
                    {
                            "ECB Response In-bound loss-less RX timestamp (usec)",
                            "appneta_rpp.ecb_resp_inbound_ll_us",
                            FT_UINT32,
                            BASE_DEC,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_ecb_resp_inbound_total_rx,
                    {
                            "ECB Response In-bound total RX (packets)",
                            "appneta_rpp.ecb_resp_inbound_total_rx",
                            FT_UINT32,
                            BASE_DEC,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_ecb_resp_inbound_total_rx_bytes,
                    {
                            "ECB Response In-bound total RX (bytes)",
                            "appneta_rpp.ecb_resp_inbound_total_rx_bytes",
                            FT_UINT64,
                            BASE_DEC,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_ecb_resp_inbound_total_us,
                    {
                            "ECB Response In-bound total RX timestamp (usec)",
                            "appneta_rpp.ecb_resp_inbound_total_us",
                            FT_UINT32,
                            BASE_DEC,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_pseudo_chksum,
                    {
                            "Pseudo Checksum",
                            "appneta_rpp.pseudo_cksum",
                            FT_UINT16,
                            BASE_HEX_DEC,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_inboundpacketcount,
                    {
                            "Inbound Packet Count",
                            "appneta_rpp.inbound_packet_count",
                            FT_UINT16,
                            BASE_DEC,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_inboundpacketsize,
                    {
                            "Inbound Packet Size",
                            "appneta_rpp.inbound_packet_size",
                            FT_UINT16,
                            BASE_DEC,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_h323port,
                    {
                            "H.323 Port",
                            "appneta_rpp.h323_port",
                            FT_UINT16,
                            BASE_DEC,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_appliance_type,
                    {
                            "Device Type",
                            "appneta_rpp.appliance_type",
                            FT_UINT8,
                            BASE_DEC,
                            VALS(ani_rpp_appliance_type_vals),
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_custom_appliance_type,
                    {
                            "Custom Type",
                            "appneta_rpp.custom_appliance_type",
                            FT_STRING,
                            BASE_NONE,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_payload,
                    {
                            "ANI Payload",
                            "appneta_rpp.payload",
                            FT_BYTES,
                            BASE_NONE,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_unknown_header,
                    {
                            "Unknown Header",
                            "appneta_rpp.unknown_header",
                            FT_BYTES,
                            BASE_NONE,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_signature_undefined,
                    {
                            "Undefined signature",
                            "appneta_signature.undefined_signature",
                            FT_BYTES,
                            BASE_NONE,
                            NULL,
                            0x0,
                            NULL, HFILL
                    }
            },
            {
                    &hf_ani_rpp_signature_legacy,
                    {
                            "AppNeta Legacy signature",
                            "appneta_signature.legacy_signature",
                            FT_BYTES,
                            BASE_NONE,
                            NULL,
                            0x0,
                            NULL, HFILL
                    }
            },
            {
                    &hf_ani_rpp_signature_path,
                    {
                            "AppNeta Path signature",
                            "appneta_signature.path_signature",
                            FT_BYTES,
                            BASE_NONE,
                            NULL,
                            0x0,
                            NULL, HFILL
                    }
            },
            {
                    &hf_ani_rpp_signature_path_reply,
                    {
                            "AppNeta Path Reply signature",
                            "appneta_signature.path_reply_signature",
                            FT_BYTES,
                            BASE_NONE,
                            NULL,
                            0x0,
                            NULL, HFILL
                    }
            },
            {
                    &hf_ani_rpp_signature_pathtest,
                    {
                            "AppNeta PathTest signature",
                            "appneta_signature.pathtest_signature",
                            FT_BYTES,
                            BASE_NONE,
                            NULL,
                            0x0,
                            NULL, HFILL
                    }
            },
            {
                    &hf_ani_rpp_signature_flags,
                    {
                            "Path flags",
                            "appneta_signature.path_flags",
                            FT_UINT8,
                            BASE_HEX,
                            NULL,
                            0x0,
                            NULL, HFILL
                    }
            },
            {
                    &hf_ani_rpp_signature_flags_first,
                    {
                            "First packet",
                            "appneta_signature.path_flags.first",
                            FT_BOOLEAN,
                            8,
                            TFS(&ani_tf_set_not_set),
                            0x10,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_signature_flags_last,
                    {
                            "Last packet",
                            "appneta_signature.path_flags.last",
                            FT_BOOLEAN,
                            8,
                            TFS(&ani_tf_set_not_set),
                            0x20,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_signature_flags_iht,
                    {
                            "Interrupt Hold Time (iht) available",
                            "appneta_signature.path_flags.iht",
                            FT_BOOLEAN,
                            8,
                            TFS(&ani_tf_set_not_set),
                            0x40,
                            NULL, HFILL
                    }
            },
            {
                    &hf_ani_rpp_signature_flags_ext,
                    {
                            "Extended Headers",
                            "appneta_signature.path_flags.ext_hdr",
                            FT_BOOLEAN,
                            8,
                            TFS(&ani_tf_set_not_set),
                            0x80,
                            NULL, HFILL
                    }
            },
            {
                    &hf_ani_rpp_signature_iht,
                    {
                            "Interrupt Hold Time (iht)",
                            "appneta_signature.iht",
                            FT_UINT32,
                            BASE_DEC,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
            {
                    &hf_ani_rpp_signature_burst_len,
                    {
                            "Burst Length",
                            "appneta_signature.burst_len",
                            FT_UINT32,
                            BASE_DEC,
                            NULL,
                            0x0,
                            "", HFILL
                    }
            },
    };

    proto_appneta_responder = proto_register_protocol(
        "AppNeta Responder Headers", /* name */
        "AppNeta_Responder", /* short name */
        "appneta_responder" /* abbrev */
    );

    register_dissector("appneta_responder", dissect_responder_header,
            proto_appneta_responder);

    /* Register the protocol name and description */
    proto_ani_rpp = proto_register_protocol("Responder Packet Protocol",
            "APPNETA_RPP", "appneta_rpp");

    proto_register_field_array(proto_ani_rpp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register preferences module */
    ani_rpp_module = prefs_register_protocol(proto_ani_rpp,
            proto_reg_handoff_ani_rpp);

    prefs_register_uint_preference(ani_rpp_module, "udp_port",
            "UDP Port",
            "The UDP port on which "
            "AppNeta Responder "
            "packets will be sent",
            10,&global_udp_port_artnet);

}


/*******************************************************************************/
/* If this dissector uses sub-dissector registration add a registration routine.
   This exact format is required because a script is used to find these
   routines and create the code that calls these routines.

   This function is also called by preferences whenever "Apply" is pressed
   (see prefs_register_protocol above) so it should accommodate being called
   more than once.
 */
void
proto_reg_handoff_ani_rpp(void)
{
    static gboolean inited = FALSE;
    static guint udp_port_ani_rpp = UDP_PORT_ANI_RPP;

    if (!inited) {
        ani_rpp_handle = create_dissector_handle(dissect_ani_rpp, proto_ani_rpp);
        inited = TRUE;
    }
    else {
        /* delete the dissector with the old port value */
        dissector_delete_uint("udp.port", udp_port_ani_rpp,ani_rpp_handle);
    }

    /* save the new port value */
    udp_port_ani_rpp = global_udp_port_artnet;

    dissector_add_uint("udp.port", global_udp_port_artnet, ani_rpp_handle);

    ip_handle = find_dissector("ip");
    payload_handle = find_dissector("appneta_payload");
}
