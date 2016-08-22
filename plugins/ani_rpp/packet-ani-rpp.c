/* packet-ani-rpp.c
 * Routines for Responder Packet Protocol dissection
 * Copyright 2007-2014 AppNeta
 *
 * $Id: packet-ani-rpp.c 23974 2007-04-04 18:21:25Z hpeterson $
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

/* Initialize the protocol and registered fields */
static int proto_ani_rpp = -1;
static guint global_udp_port_artnet = UDP_PORT_ANI_RPP;
static gboolean show_ani_payload = TRUE;

/* Responder packet fields */
static int hf_ani_rpp_next_header_type = -1;
static int hf_ani_rpp_header_length = -1;
static int hf_ani_rpp_pkt_id = -1;
static int hf_ani_rpp_flow_num = -1;
static int hf_ani_rpp_flow_port = -1;
static int hf_ani_rpp_flow_port_first = -1;
static int hf_ani_rpp_flow_port_last = -1;
static int hf_ani_rpp_test_weight = -1;
static int hf_ani_rpp_error_code = -1;
static int hf_ani_rpp_response_status = -1;
static int hf_ani_rpp_responder_version_major = -1;
static int hf_ani_rpp_responder_version_minor = -1;
static int hf_ani_rpp_responder_version_revision = -1;
static int hf_ani_rpp_responder_version_build = -1;
static int hf_ani_rpp_unknown_header = -1;
static int hf_ani_rpp_burst_size = -1;
static int hf_ani_rpp_packet_size = -1;
static int hf_ani_rpp_command_type = -1;
static int hf_ani_rpp_first_id = -1;
static int hf_ani_rpp_outbound_arrival_bits = -1;
static int hf_ani_burst_hold_time_us = -1;
static int hf_ani_burst_process_time_us = -1;
static int hf_ani_rpp_outbound_arrival_times = -1;
static int hf_ani_rpp_lost_id = -1;
static int hf_ani_rpp_sipport = -1;
static int hf_ani_rpp_ta_id = -1;
static int hf_ani_rpp_protocol = -1;
static int hf_ani_rpp_cb_inbound_packetcount = -1;
static int hf_ani_rpp_cb_inbound_interpacketgap = -1;
static int hf_ani_rpp_cb_outbound_packetcount = -1;
static int hf_ani_rpp_cb_outbound_interpacketgap = -1;
static int hf_ani_rpp_cb_resp_ratelimitcbrate = -1;
static int hf_ani_rpp_cb_resp_minpacketcount = -1;
static int hf_ani_rpp_cb_flags_resp_csv_debug = -1;
static int hf_ani_rpp_inboundpacketcount = -1;
static int hf_ani_rpp_inboundpacketsize = -1;
static int hf_ani_rpp_h323port = -1;
static int hf_ani_rpp_appliance_type = -1;
static int hf_ani_rpp_custom_appliance_type = -1;
static int hf_ani_rpp_command_flags = -1;
static int hf_ani_rpp_command_flags_is_jumbo = -1;
static int hf_ani_rpp_command_flags_is_super_jumbo = -1;
static int hf_ani_rpp_command_flags_is_inbound = -1;
static int hf_ani_rpp_payload = -1;

/* RTP header fields                                 */
/* Assumptions about RTP: no padding, no extensions, */
/* and no CSRC identifiers (i.e. 12 bytes only)      */
static int hf_rtp_version      = -1;
static int hf_rtp_padding      = -1;
static int hf_rtp_extension    = -1;
static int hf_rtp_csrc_count   = -1;
static int hf_rtp_marker       = -1;
static int hf_rtp_payload_type = -1;
static int hf_rtp_seq_nr       = -1;
static int hf_rtp_ext_seq_nr   = -1;
static int hf_rtp_timestamp    = -1;
static int hf_rtp_ssrc         = -1;

/* Initialize the subtree pointers */
static gint ett_ani_rpp = -1;
static gint ett_ani_rtp = -1;
static gint ett_ani_seq = -1;
static gint ett_ani_err = -1;
static gint ett_ani_reply = -1;
static gint ett_ani_flow_create = -1;
static gint ett_ani_flow_response = -1;
static gint ett_ani_flow_close = -1;
static gint ett_ani_test_weight = -1;
static gint ett_ani_responder_version = -1;
static gint ett_ani_burst_info = -1;
static gint ett_ani_outbound_arrival = -1;
static gint ett_ani_burst_hold_time = -1;
static gint ett_ani_outbound_arrival_times = -1;
static gint ett_ani_lost_pkts = -1;
static gint ett_ani_sipport = -1;
static gint ett_ani_protocol = -1;
static gint ett_ani_controlledburst = -1;
static gint ett_ani_controlledburstresponse = -1;
static gint ett_ani_inboundpacketattr = -1;
static gint ett_ani_h323port = -1;
static gint ett_ani_appliance_type = -1;
static gint ett_ani_custom_appliance_type = -1;
static gint ett_ani_payload = -1;

/* an array of pointers to the above subtree index and pointervalues */
static int* hf_subtrees[] = {
  NULL,
  NULL,
  &ett_ani_seq,
  &ett_ani_err,
  NULL,
  &ett_ani_reply,
  &ett_ani_flow_create,
  &ett_ani_flow_response,
  &ett_ani_flow_close,
  &ett_ani_test_weight,
  NULL,
  NULL,
  &ett_ani_burst_info,
  &ett_ani_responder_version,
  &ett_ani_outbound_arrival,
  &ett_ani_burst_hold_time,
  &ett_ani_outbound_arrival_times,
  &ett_ani_lost_pkts,
  &ett_ani_sipport,
  &ett_ani_protocol,
  &ett_ani_controlledburst,
  &ett_ani_controlledburstresponse,
  &ett_ani_inboundpacketattr,
  &ett_ani_h323port,
  &ett_ani_appliance_type,
  &ett_ani_custom_appliance_type,
  &ett_ani_payload,
};

enum ResponderHeaderType
{HDR_LAST = 1,
HDR_SEQUENCE,
HDR_ERROR,
HDR_REQUEST,
HDR_REPLY, //5
HDR_FLOW_CREATE,
HDR_FLOW_RESPONSE,
HDR_FLOW_CLOSE,
HDR_TEST_WEIGHT,
HDR_TEST_PARAMS, //10
HDR_FLOW_PACKET, //not actually a header, used to report flow not found
HDR_COMMAND_INFO,
HDR_RESPONDERVERSION,
HDR_OUTBOUNDARRIVAL,
HDR_RESPONDERHOLDTIME,
HDR_OUTBOUNDARRIVALTIME,
HDR_LOST_PACKETS,
HDR_SIPPORT,
HDR_PROTOCOL,
HDR_CONTROLLEDBURST,
HDR_CONTROLLEDBURSTRESPONSE,
HDR_INBOUNDPACKETATTR,
HDR_H323PORT,
HDR_APPLIANCE_TYPE,
HDR_CUSTOM_APPLIANCE_TYPE,
HDR_INVALID,
HDR_COUNT} ResponderHeaderType;

/* strings to make protocol parsing more readable */
static const value_string rtp_version_vals[] =
{
  { 0, "Old VAT Version" },
  { 1, "First Draft Version" },
  { 2, "RFC 1889 Version" },
  { 0, NULL },
};

static const value_string ani_rpp_header_type_vals[] =
{
  { 1, "No more headers" },
  { 2, "Sequence" },
  { 3, "Error" },
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
  { 14, "Outbound arrival bits" },
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
  { 25, "Custom Type" },
  { 26, "Invalid Header" },
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
  { 0, "Invalid" },
  { 0x81, "Burst with Primer" },
  { 0x82, "Datagram with Primer" },
  { 0x83, "Controlled Burst with Primer" },
  { 0x84, "Tight Datagram with Primer" },
  { 0x85, "Burst Load with Primer" },
  { 0, NULL }
};

static const value_string ani_rpp_appliance_type_vals[] =
{
  { 0, "Invalid" },
  { 1, "Windows" },
  { 2, "Linux" },
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
  { 13, "Custom" },
  { 14, "Unknown" },
  { 15, "Unknown" },
  { 0, NULL }
};

static const unsigned char ANI_PAYLOAD_SIGNATURE[] = { 0xEC, 0xBD, 0x7F, 0x60, 0xFF };
static const unsigned char ANI_LEGACY_PAYLOAD_SIGNATURE[] = { 0xEC, 0xBD, 0x7F, 0x60, 0x54, 0xD5 };
static const unsigned char PATHTEST_PAYLOAD_SIGNATURE[] = { 0xEC, 0xBD, 0x7F, 0x60, 0xFE };

/*******************************************************************/
/* Parse the RTP header and return the number of bytes processed.
 * If ani_rpp_tree is set to NULL just return the length of
 * the header; otherwise add items to the dissector tree.
*/
static int
dissect_rtp_header(tvbuff_t *tvb, packet_info *pinfo _U_, int offset,
    proto_tree *ani_rpp_tree, gboolean *marker_set)
{
  guint8        octet1, octet2;
  unsigned int  version;
  gboolean      padding_set;
  gboolean      extension_set;
  unsigned int  csrc_count;
  unsigned int  payload_type;
  guint16       seq_num;
  guint32       timestamp;
  guint32       sync_src;
  proto_tree*   rtp_tree = NULL;

  *marker_set = 0;

  /* Get the fields in the first octet */
  octet1 = tvb_get_guint8( tvb, offset );
  octet2 = tvb_get_guint8( tvb, offset + 1 );

  if (octet1 != 0x80 || (octet2 & 0x7F) != 0x02) {
    /* this is not an RTP header, so return 0 bytes processed */
    return 0;
  }

  if (ani_rpp_tree == NULL) {
    /* just return the length without adding items to the dissector tree */
    return RTP_HEADER_LENGTH;
  }

  /* parse the rtp header, adding items to the dissector tree */

  /* get the fields in the first octet */
  version = RTP_VERSION( octet1 );
  padding_set = RTP_PADDING( octet1 );
  extension_set = RTP_EXTENSION( octet1 );
  csrc_count = RTP_CSRC_COUNT( octet1 );

  /* Get the fields in the second octet */
  *marker_set = RTP_MARKER( octet2 );
  payload_type = RTP_PAYLOAD_TYPE( octet2 );

  /* Get the subsequent fields */
  seq_num = tvb_get_ntohs( tvb, offset + 2 );
  timestamp = tvb_get_ntohl( tvb, offset + 4 );
  sync_src = tvb_get_ntohl( tvb, offset + 8 );

  /* Create a subtree for RTP */
  if (sync_src == NO_FLOW) {
    rtp_tree = proto_tree_add_subtree_format(ani_rpp_tree, tvb, offset, RTP_HEADER_LENGTH, ett_ani_rtp, NULL,
        "Responder RTP Header: No flow, %s", *marker_set ? "Dual-ended" : "Single-ended");
  } else {
    rtp_tree = proto_tree_add_subtree_format(ani_rpp_tree, tvb, offset, RTP_HEADER_LENGTH, ett_ani_rtp, NULL,
      "Responder RTP Header: Flow %u, %s", sync_src, *marker_set ? "Dual-ended" : "Single-ended");
  }

  /* Add items to the RTP subtree */
  proto_tree_add_uint( rtp_tree, hf_rtp_version, tvb, offset, 1, octet1 );
  proto_tree_add_boolean( rtp_tree, hf_rtp_padding, tvb, offset, 1, octet1 );
  proto_tree_add_boolean( rtp_tree, hf_rtp_extension, tvb, offset, 1, octet1 );
  proto_tree_add_uint( rtp_tree, hf_rtp_csrc_count, tvb, offset, 1, octet1 );
  offset++;

  proto_tree_add_boolean( rtp_tree, hf_rtp_marker, tvb, offset,
    1, octet2 );
  /*
  proto_tree_add_uint_format( ani_rpp_tree, hf_rtp_payload_type, tvb,
  offset, 1, octet2, "Payload type: %s (%u)",
  payload_type_str ? payload_type_str : val_to_str( payload_type, rtp_payload_type_vals,"Unknown"),
  payload_type);
  */
  offset++;

  /* Sequence number 16 bits (2 octets) */
  proto_tree_add_uint( rtp_tree, hf_rtp_seq_nr, tvb, offset, 2, seq_num );
  offset += 2;

  /* Timestamp 32 bits (4 octets) */
  proto_tree_add_uint( rtp_tree, hf_rtp_timestamp, tvb, offset, 4, timestamp );
  offset += 4;

  /* Synchronization source identifier 32 bits (4 octets) */
  proto_tree_add_uint( rtp_tree, hf_rtp_ssrc, tvb, offset, 4, sync_src );
  offset += 4;

  return offset;
}

static proto_tree *add_subtree(tvbuff_t *tvb, gint *offset, proto_tree *current_tree,
    gint header, gint8 headerLength, const char *title)
{
  proto_tree *tree = NULL;

  if (current_tree && hf_subtrees[header]) {
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
static int
dissect_responder_header(tvbuff_t *tvb, packet_info *pinfo, gint offset, proto_tree *ani_rpp_tree)
{
  gint currentHeader, nextHeader;
  guint8 headerLength = 0, mainHeader = 1, mode = 0;
  guint8 cmd_info_flags = 0;
  guint32 id, flow, major, minor, revision, build, first_id,
    burst_hold_time, i, depth;
  guint16 port, portend, weight, burstsize, packetsize;
  proto_tree   *current_tree = NULL, *field_tree = NULL;
  proto_item   *ti = NULL, *tf = NULL;
  tvbuff_t *next_tvb;
  gboolean   save_in_error_pkt;

  currentHeader = HDR_SEQUENCE;
  while (currentHeader != HDR_LAST && currentHeader < HDR_INVALID) {
    current_tree = ani_rpp_tree;
    nextHeader = tvb_get_guint8( tvb, offset );
    headerLength = tvb_get_guint8( tvb, offset+1 );

    switch (currentHeader)
    {
    case HDR_SEQUENCE:
      current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
          "Sequence Header");
      if (current_tree) {
        id = tvb_get_ntohl( tvb, offset );
        proto_tree_add_item( current_tree, hf_ani_rpp_pkt_id, tvb, offset, 4, FALSE );

        /* set some text in the info column */
        col_add_fstr(pinfo->cinfo, COL_INFO, "Responder Packet: ID %d(0x%x)", id, id);
      }
      offset += (headerLength - 2);
      break;
    case HDR_ERROR:
      current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
          "Error Header");
      if (current_tree) {
        proto_tree_add_item( current_tree, hf_ani_rpp_error_code, tvb, offset, 1, FALSE );
        proto_tree_add_item( current_tree, hf_ani_rpp_next_header_type, tvb, offset+1, 1, FALSE );

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
          call_dissector( ip_handle, next_tvb, pinfo, current_tree );
        }

        /* Restore the "we're inside an error packet" flag. */
        pinfo->flags.in_error_pkt = save_in_error_pkt;

        /* set some text in the info column */
        col_append_str(pinfo->cinfo, COL_INFO, " Reply");
        mainHeader = 0;
      }
      offset += (headerLength - 2);
      break;
    case HDR_FLOW_CREATE:
      current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
          "Create Flow Header");
      if (current_tree) {
        port = tvb_get_ntohs( tvb, offset );
        if (headerLength >= 6) {
          proto_tree_add_item( current_tree, hf_ani_rpp_flow_port_first, tvb, offset, 2, FALSE );
          proto_tree_add_item( current_tree, hf_ani_rpp_flow_port_last, tvb, offset, 4, FALSE );
        } else {
          proto_tree_add_item( current_tree, hf_ani_rpp_flow_port, tvb, offset, 2, FALSE );
        }

        /* set some text in the info column */
        if (headerLength >= 6) {
          portend = tvb_get_ntohs( tvb, offset+2 );
          col_append_fstr(pinfo->cinfo, COL_INFO, " Create Flows (ports %d through %d)", port, portend);
        } else {
          col_append_fstr(pinfo->cinfo, COL_INFO, " Create Flow (port %d)", port);
        }
        mainHeader = 0;
      }
      offset += (headerLength - 2);
      break;
    case HDR_FLOW_RESPONSE:
      current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
          "Reply Header");
      if (current_tree) {
        flow = tvb_get_ntohl( tvb, offset );
        port = tvb_get_ntohs( tvb, offset+4 );
        proto_tree_add_item ( current_tree, hf_ani_rpp_flow_num, tvb, offset, 4, FALSE );
        proto_tree_add_item( current_tree, hf_ani_rpp_flow_port, tvb, offset+4, 2, FALSE );
        proto_tree_add_item( current_tree, hf_ani_rpp_response_status, tvb, offset+6, 2, FALSE );

        /* tell Wireshark to dissect packets addressed to hf_ani_rpp_flow_port
         * using this dissector.
         */
        if (port != UDP_PORT_ANI_RPP)
          dissector_add_uint("udp.port", port, ani_rpp_handle);

        /* set some text in the info column */
        col_append_fstr(pinfo->cinfo, COL_INFO, " Flow Response (flow ID %d)", flow);
        mainHeader = 0;
      }
      offset += (headerLength - 2);
      break;
    case HDR_FLOW_CLOSE:
      current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
          "Close Flow Header");
      if (current_tree) {
        flow = tvb_get_ntohl( tvb, offset );
        proto_tree_add_item ( current_tree, hf_ani_rpp_flow_num, tvb, offset, 4, FALSE );
        proto_tree_add_item( current_tree, hf_ani_rpp_flow_port, tvb, offset+4, 2, FALSE );
        proto_tree_add_item( current_tree, hf_ani_rpp_response_status, tvb, offset+6, 2, FALSE );

        /* set some text in the info column */
        col_append_fstr(pinfo->cinfo, COL_INFO, " Close Flow (flow ID %d)", flow);
        mainHeader = 0;
      }
      offset += (headerLength - 2);
      break;
    case HDR_TEST_WEIGHT:
      current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
          "Test Weight Header");
      if (current_tree) {
        weight = tvb_get_ntohs( tvb, offset );
        proto_tree_add_item( current_tree, hf_ani_rpp_test_weight, tvb, offset, 2, FALSE );

        /* set some text in the info column */
        col_append_fstr(pinfo->cinfo, COL_INFO, " (weight %d)", weight);
      }
      offset += (headerLength - 2);
      break;
    case HDR_RESPONDERVERSION:
      current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
          "Responder Version Header");
      if (current_tree) {
        major = tvb_get_ntohl( tvb, offset );
        minor = tvb_get_ntohl( tvb, offset+4 );
        revision = tvb_get_ntohl( tvb, offset+8 );
        build = tvb_get_ntohl( tvb, offset+12 );
        proto_tree_add_item( current_tree, hf_ani_rpp_responder_version_major, tvb, offset, 4, FALSE );
        proto_tree_add_item( current_tree, hf_ani_rpp_responder_version_minor, tvb, offset+4, 4, FALSE );
        proto_tree_add_item( current_tree, hf_ani_rpp_responder_version_revision, tvb, offset+8, 4, FALSE );
        proto_tree_add_item( current_tree, hf_ani_rpp_responder_version_build, tvb, offset+12, 4, FALSE );

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
        burstsize = tvb_get_ntohs( tvb, offset+4 );
        packetsize = tvb_get_ntohs( tvb, offset+6 );
        proto_tree_add_item( current_tree, hf_ani_rpp_first_id, tvb, offset, 4, FALSE );
        proto_tree_add_item( current_tree, hf_ani_rpp_burst_size, tvb, offset+4, 2, FALSE );
        if (headerLength > 8) {
          proto_tree_add_item( current_tree, hf_ani_rpp_packet_size, tvb, offset+6, 2, FALSE );
        }
        if (headerLength >= 11) {
          proto_tree_add_item( current_tree, hf_ani_rpp_command_type, tvb, offset+8, 1, FALSE );
          mode = tvb_get_guint8( tvb, offset+8 );
        }
        if (headerLength >= 12) {
          cmd_info_flags = tvb_get_guint8( tvb, offset + 9 );
          tf = proto_tree_add_uint( current_tree, hf_ani_rpp_command_flags, tvb, offset+9, 1, cmd_info_flags );
          field_tree = proto_item_add_subtree( tf, ett_ani_burst_info );
          proto_tree_add_boolean( field_tree, hf_ani_rpp_command_flags_is_jumbo, tvb, offset+9, 1, cmd_info_flags );
          proto_tree_add_boolean( field_tree, hf_ani_rpp_command_flags_is_super_jumbo, tvb, offset+9, 1, cmd_info_flags );
          proto_tree_add_boolean( field_tree, hf_ani_rpp_command_flags_is_inbound, tvb, offset+9, 1, cmd_info_flags );
        }

        /* set some text in the info column */
        if (mode == 1) {
          col_append_fstr(pinfo->cinfo, COL_INFO, ", Burst");
        } else if (mode == 2) {
          col_append_fstr(pinfo->cinfo, COL_INFO, ", Datagram");
        } else if (mode == 3) {
          if ((cmd_info_flags & 0x4)) {
            col_append_fstr(pinfo->cinfo, COL_INFO, ", Inbound Controlled Burst");
          } else
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
        proto_tree_add_item( current_tree, hf_ani_rpp_outbound_arrival_bits, tvb, offset, 8, FALSE );

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
        //burst_process_time = tvb_get_ntohl( tvb, offset+4);
        proto_tree_add_item( current_tree, hf_ani_burst_hold_time_us, tvb, offset, 4, FALSE );
        //proto_tree_add_item( current_tree, hf_ani_burst_process_time_us, tvb, offset+4, 4, FALSE );

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
          proto_tree_add_item( current_tree, hf_ani_rpp_outbound_arrival_times, tvb, offset+i, 4, FALSE );
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
          proto_tree_add_item( current_tree, hf_ani_rpp_lost_id, tvb, offset+i, 4, FALSE );
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
        proto_tree_add_item( current_tree, hf_ani_rpp_sipport, tvb, offset, 2, FALSE );
        proto_tree_add_item( current_tree, hf_ani_rpp_ta_id, tvb, offset + 2, idLength, FALSE );
      }
      offset += (headerLength - 2);
      break;
    case HDR_PROTOCOL:
      current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
          "Protocol");
      if (current_tree) {
        proto_tree_add_item( current_tree, hf_ani_rpp_protocol, tvb, offset, 4, FALSE );
      }
      offset += (headerLength - 2);
      break;
    case HDR_CONTROLLEDBURST:
      current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
          "Controlled Burst");
      if (current_tree) {
        proto_tree_add_item ( current_tree, hf_ani_rpp_cb_inbound_packetcount, tvb, offset, 4, FALSE );
        proto_tree_add_item( current_tree, hf_ani_rpp_cb_inbound_interpacketgap, tvb, offset+4, 4, FALSE );
        tf = proto_tree_add_uint( current_tree, hf_ani_rpp_command_flags, tvb, offset+4, 1, cmd_info_flags );
        field_tree = proto_item_add_subtree( tf, ett_ani_burst_info );
        proto_tree_add_boolean( field_tree, hf_ani_rpp_cb_flags_resp_csv_debug, tvb, offset+4, 1, tvb_get_guint32( tvb, offset + 4 ) );
        if (headerLength >= 18) {
          proto_tree_add_item ( current_tree, hf_ani_rpp_cb_outbound_packetcount, tvb, offset+8, 4, FALSE );
          proto_tree_add_item( current_tree, hf_ani_rpp_cb_outbound_interpacketgap, tvb, offset+12, 4, FALSE );
        }
      }
      offset += (headerLength - 2);
      break;
    case HDR_CONTROLLEDBURSTRESPONSE:
      current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
          "Controlled Burst Response");
      if (current_tree) {
        proto_tree_add_item ( current_tree, hf_ani_rpp_cb_resp_ratelimitcbrate, tvb, offset, 4, FALSE );
        proto_tree_add_item( current_tree, hf_ani_rpp_cb_resp_minpacketcount, tvb, offset+4, 4, FALSE );
      }
      offset += (headerLength - 2);
      break;
    case HDR_INBOUNDPACKETATTR:
      current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
          "Inbound Packet Attributes");
      if (current_tree) {
        proto_tree_add_item ( current_tree, hf_ani_rpp_inboundpacketcount, tvb, offset, 2, FALSE );
        proto_tree_add_item( current_tree, hf_ani_rpp_inboundpacketsize, tvb, offset+2, 2, FALSE );
        burstsize = tvb_get_ntohs( tvb, offset );
        col_append_fstr(pinfo->cinfo, COL_INFO, "/%d (out/in)", burstsize);
      }
      offset += (headerLength - 2);
      break;
    case HDR_H323PORT:
      current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
          "H.323");
      if (current_tree) {
        proto_tree_add_item ( current_tree, hf_ani_rpp_h323port, tvb, offset, 2, FALSE );
      }
      offset += (headerLength - 2);
      break;
    case HDR_APPLIANCE_TYPE:
      current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
          "Device Type");
      if (current_tree) {
        proto_tree_add_item ( current_tree, hf_ani_rpp_appliance_type, tvb, offset, 1, FALSE );
      }
      offset += (headerLength - 2);
      break;
    case HDR_CUSTOM_APPLIANCE_TYPE:
      current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
          "Custom Type");
      if (current_tree) {
        proto_tree_add_item ( current_tree, hf_ani_rpp_custom_appliance_type, tvb, offset, headerLength - 2, FALSE );
      }
      offset += (headerLength - 2);
      break;
    default:
      current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
          "Unknown Header");
      if (current_tree) {
        proto_tree_add_item( current_tree, hf_ani_rpp_unknown_header, tvb, offset, headerLength-2, FALSE );

        /* set some text in the info column */
        col_append_str(pinfo->cinfo, COL_INFO, " [Unknown Header]");

      }
      offset += (headerLength - 2);
      return offset;
    }
    currentHeader = nextHeader;
  }

  return offset;
}

/*******************************************************************/
/* Code to actually dissect the packets
*/
static int
dissect_ani_rpp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  unsigned int offset = 0;
  gboolean      marker_set;

  /* Make entries in Protocol column and Info column on summary display */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "ani-rpp");
  col_set_str(pinfo->cinfo, COL_INFO, "ANI-RPP Request");
  col_clear(pinfo->cinfo, COL_INFO);

  /* determine how many bytes of the packet will be processed */
  offset = dissect_rtp_header(tvb, pinfo, offset, NULL, &marker_set);
  offset = dissect_responder_header(tvb, pinfo, offset, NULL);

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
    offset = dissect_responder_header(tvb, pinfo, offset, ani_rpp_tree);
    call_dissector(payload_handle, tvb_new_subset(tvb, offset, -1, -1), pinfo, tree);
  }
  col_append_fstr(pinfo->cinfo, COL_INFO, marker_set ? ", Dual-ended" : ", Single-ended");

  /* Return the amount of data this dissector was able to dissect */
  return tvb_captured_length(tvb);
}

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
          "ani-rpp.type",
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
          "ani-rpp.hdrLength",
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
          "ani-rpp.pktId",
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
          "ani-rpp.errCode",
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
          "ani-rpp.status",
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
          "ani-rpp.flowNum",
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
          "ani-rpp.flowPort",
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
          "ani-rpp.flowPortFirst",
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
          "ani-rpp.flowPortLast",
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
          "ani-rpp.testWeight",
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
          "ani-rpp.responderVersionMajor",
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
          "ani-rpp.responderVersionMinor",
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
          "ani-rpp.responderVersionRevision",
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
          "ani-rpp.responderVersionBuild",
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
          "ani-rpp.burstSize",
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
          "ani-rpp.packetSize",
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
          "ani-rpp.commandType",
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
          "ani-rpp.first_id",
          FT_UINT32,
          BASE_DEC,
          NULL,
          0x0,
          "", HFILL
      }
    },
    {
      &hf_ani_rpp_outbound_arrival_bits,
      {
        "Outbound Arrival Bits",
          "ani-rpp.outboundbits",
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
          "ani-rpp.burst_hold_time",
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
          "ani-rpp.resp_csv_debug",
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
          "ani-rpp.commandFlags",
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
          "ani-rpp.is_jumbo",
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
          "ani-rpp.is_super_jumbo",
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
          "ani-rpp.is_inbound",
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
          "ani-rpp.burst_proc_time",
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
          "ani-rpp.outboundtimes",
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
          "ani-rpp.lost_id",
          FT_UINT32,
          BASE_DEC,
          NULL,
          0x0,
          "", HFILL
      }
    },
    {
      &hf_ani_rpp_sipport,
      {
        "Sip Port",
          "ani-rpp.sipport",
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
          "ani-rpp.ta_id",
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
          "ani-rpp.protocol",
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
          "ani-rpp.cb_inbound_packetcount",
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
          "ani-rpp.cb_inbound_interpacketgap",
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
          "ani-rpp.cb_outbound_packetcount",
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
          "ani-rpp.cb_outbound_interpacketgap",
          FT_UINT32,
          BASE_DEC,
          NULL,
          0x0,
          "", HFILL
      }
    },
    {
      &hf_ani_rpp_cb_resp_ratelimitcbrate,
      {
        "Rate Limit CB Rate",
          "ani-rpp.cb_resp_ratelimitcbrate",
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
          "ani-rpp.cb_resp_minpacketcount",
          FT_UINT32,
          BASE_DEC,
          NULL,
          0x0,
          "", HFILL
      }
    },
    {
      &hf_ani_rpp_inboundpacketcount,
      {
        "Inbound Packet Count",
          "ani-rpp.inboundpacketcount",
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
          "ani-rpp.inboundpacketsize",
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
          "ani-rpp.h323port",
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
          "ani-rpp.appliance_type",
          FT_UINT8,
          BASE_HEX,
          VALS(ani_rpp_appliance_type_vals),
          0x0,
          "", HFILL
      }
    },
    {
      &hf_ani_rpp_custom_appliance_type,
      {
        "Custom Type",
          "ani-rpp.custom_appliance_type",
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
          "ani-rpp.payload",
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
          "ani-rpp.unknownHeader",
          FT_BYTES,
          BASE_NONE,
          NULL,
          0x0,
          "", HFILL
      }
    },
  };

  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_ani_rpp,
    &ett_ani_rtp,
    &ett_ani_seq,
    &ett_ani_err,
    &ett_ani_reply,
    &ett_ani_flow_create,
    &ett_ani_flow_response,
    &ett_ani_flow_close,
    &ett_ani_test_weight,
    &ett_ani_burst_info,
    &ett_ani_responder_version,
    &ett_ani_outbound_arrival,
    &ett_ani_burst_hold_time,
    &ett_ani_outbound_arrival_times,
    &ett_ani_lost_pkts,
    &ett_ani_sipport,
    &ett_ani_protocol,
    &ett_ani_controlledburst,
    &ett_ani_controlledburstresponse,
    &ett_ani_inboundpacketattr,
    &ett_ani_h323port,
    &ett_ani_appliance_type,
    &ett_ani_custom_appliance_type,
    &ett_ani_payload,
  };

  /* Register the protocol name and description */
  proto_ani_rpp = proto_register_protocol("Responder Packet Protocol",
                                            "ANI-RPP", "ani-rpp");


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

  prefs_register_bool_preference(ani_rpp_module,
    "show_ani_payload",
    "Show dissected ANI payload",
    "Show dissected ANI payload in the Packet Details pane",
    &show_ani_payload);
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
      ani_rpp_handle = new_create_dissector_handle(dissect_ani_rpp, proto_ani_rpp);
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
  payload_handle = find_dissector("ani_payload");
}
