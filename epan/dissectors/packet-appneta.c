/*
 * packet-appneta.c
 *
 * Packet protocol for AppNeta
 * https://techdocs.broadcom.com/us/en/ca-enterprise-software/it-operations-management/appneta/GA.html
 *
 * Copyright (c) 2025, Broadcom Inc.
 * By Fred Klassen <fred.klassen@broadcom.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <epan/dissectors/packet-ipv6.h>
#include <epan/ipproto.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/proto.h>
#include <wsutil/str_util.h>

const uint8_t APPNETA_PAYLOAD_SIGNATURE[]                = { 0xEC, 0xBD, 0x7F, 0x60, 0xFF };
const uint8_t APPNETA_REPLY_PAYLOAD_SIGNATURE[]          = { 0xEC, 0xBD, 0x7F, 0x60, 0xFD };
const uint8_t APPNETA_LEGACY_PAYLOAD_SIGNATURE[]         = { 0xEC, 0xBD, 0x7F, 0x60, 0x54, 0xD5 };
const uint8_t APPNETA_LEGACY_PAYLOAD_SIGNATURE_CORRUPT[] = { 0xEC, 0xBD, 0x7F, 0x60, 0x54 };
const uint8_t PATHTEST_PAYLOAD_SIGNATURE[]               = { 0xEC, 0xBD, 0x7F, 0x60, 0xFE };

enum appneta_pkt_type {
    APPNETA_PACKET_TYPE_UNDEFINED,
    APPNETA_PACKET_TYPE_PATH,
    APPNETA_PACKET_TYPE_PATH_REPLY,
    APPNETA_PACKET_TYPE_LEGACY,
    APPNETA_PACKET_TYPE_PATHTEST,
};
typedef enum appneta_pkt_type appneta_pkt_type_t;

#define UDP_PORT_APPNETA_RESP 3239
#define RTP_HEADER_LENGTH     12
#define NO_FLOW               0xffffffff

/* Initialize the protocol and registered fields */
static int proto_appneta_resp;

/* Initialize the subtree pointers */
static int ett_appneta_resp;

void proto_register_appneta(void);
void proto_reg_handoff_appneta(void);
void proto_handoff_appneta_payload(void);

/* Responder packet fields */
static int hf_appneta_resp_next_header_type;
static int hf_appneta_resp_header_length;
static int hf_appneta_resp_pkt_id;
static int hf_appneta_resp_flow_num;
static int hf_appneta_resp_flow_port;
static int hf_appneta_resp_flow_port_first;
static int hf_appneta_resp_flow_port_last;
static int hf_appneta_resp_test_weight;
static int hf_appneta_resp_error_code;
static int hf_appneta_resp_error_value;
static int hf_appneta_resp_response_status;
static int hf_appneta_resp_responder_version_major;
static int hf_appneta_resp_responder_version_minor;
static int hf_appneta_resp_responder_version_revision;
static int hf_appneta_resp_responder_version_build;
static int hf_appneta_resp_unknown_header;
static int hf_appneta_resp_burst_size;
static int hf_appneta_resp_packet_size;
static int hf_appneta_resp_command_type;
static int hf_appneta_resp_first_id;
static int hf_appneta_resp_outbound_arrival_bits;
static int hf_appneta_resp_burst_hold_time_us;
static int hf_appneta_resp_outbound_arrival_times;
static int hf_appneta_resp_lost_id;
static int hf_appneta_resp_sipport;
static int hf_appneta_resp_ta_id;
static int hf_appneta_resp_protocol;
static int hf_appneta_resp_cb_inbound_packetcount;
static int hf_appneta_resp_cb_inbound_interpacketgap;
static int hf_appneta_resp_cb_outbound_packetcount;
static int hf_appneta_resp_cb_outbound_interpacketgap;
static int hf_appneta_resp_cb_inbound_flags_csv_debug;
static int hf_appneta_resp_cb_resp_ratelimitcbrate;
static int hf_appneta_resp_cb_resp_minpacketcount;
static int hf_appneta_resp_iface_info_flags;
static int hf_appneta_resp_iface_info_flags_is_appneta_resp_modified;
static int hf_appneta_resp_iface_info_mtu;
static int hf_appneta_resp_iface_info_speed;
static int hf_appneta_resp_inboundpacketcount;
static int hf_appneta_resp_inboundpacketsize;
static int hf_appneta_resp_h323port;
static int hf_appneta_resp_appliance_type;
static int hf_appneta_resp_custom_appliance_type;
static int hf_appneta_resp_command_flags;
static int hf_appneta_resp_command_flags_is_jumbo;
static int hf_appneta_resp_command_flags_is_super_jumbo;
static int hf_appneta_resp_command_flags_is_inbound;
static int hf_appneta_resp_cb_request_reserved1;
static int hf_appneta_resp_cb_request_reserved2;
static int hf_appneta_resp_cb_ready_reserved1;
static int hf_appneta_resp_cb_ready_reserved2;
static int hf_appneta_resp_ecb_request_padding;
static int hf_appneta_resp_ecb_request_flags;
static int hf_appneta_resp_ecb_request_flags_first_seq;
static int hf_appneta_resp_ecb_request_flags_last_seq;
static int hf_appneta_resp_ecb_request_flags_reply;
static int hf_appneta_resp_ecb_request_flags_rx_report_all;
static int hf_appneta_resp_ecb_request_flags_inbound_gap_ns;
static int hf_appneta_resp_ecb_request_flags_outbound_gap_ns;
static int hf_appneta_resp_ecb_request_ssn;
static int hf_appneta_resp_ecb_request_outbound_magnify;
static int hf_appneta_resp_ecb_request_outbound_duration;
static int hf_appneta_resp_ecb_request_outbound_gap;
static int hf_appneta_resp_ecb_request_inbound_magnify;
static int hf_appneta_resp_ecb_request_inbound_duration;
static int hf_appneta_resp_ecb_request_inbound_gap;
static int hf_appneta_resp_ecb_request_outbound_max_packets;
static int hf_appneta_resp_ecb_request_inbound_max_packets;
static int hf_appneta_resp_ecb_resp_padding;
static int hf_appneta_resp_ecb_resp_flags;
static int hf_appneta_resp_ecb_resp_flags_in;
static int hf_appneta_resp_ecb_resp_flags_out;
static int hf_appneta_resp_ecb_resp_flags_final;
static int hf_appneta_resp_ecb_resp_outbound_first_tx_ts;
static int hf_appneta_resp_ecb_resp_outbound_first_rx_ts;
static int hf_appneta_resp_ecb_resp_outbound_ll_rx;
static int hf_appneta_resp_ecb_resp_outbound_ll_rx_bytes;
static int hf_appneta_resp_ecb_resp_outbound_ll_us;
static int hf_appneta_resp_ecb_resp_outbound_total_rx;
static int hf_appneta_resp_ecb_resp_outbound_total_rx_bytes;
static int hf_appneta_resp_ecb_resp_outbound_total_us;
static int hf_appneta_resp_ecb_resp_inbound_first_tx_ts;
static int hf_appneta_resp_ecb_resp_inbound_first_rx_ts;
static int hf_appneta_resp_ecb_resp_inbound_ll_rx;
static int hf_appneta_resp_ecb_resp_inbound_ll_rx_bytes;
static int hf_appneta_resp_ecb_resp_inbound_ll_us;
static int hf_appneta_resp_ecb_resp_inbound_total_rx;
static int hf_appneta_resp_ecb_resp_inbound_total_rx_bytes;
static int hf_appneta_resp_ecb_resp_inbound_total_us;
static int hf_appneta_resp_pseudo_chksum;
static int hf_appneta_resp_signature_undefined;
static int hf_appneta_resp_signature_path;
static int hf_appneta_resp_signature_path_reply;
static int hf_appneta_resp_signature_legacy;
static int hf_appneta_resp_signature_pathtest;
static int hf_appneta_resp_signature_flags;
static int hf_appneta_resp_signature_flags_first;
static int hf_appneta_resp_signature_flags_last;
static int hf_appneta_resp_signature_flags_iht;
static int hf_appneta_resp_signature_flags_ext;
static int hf_appneta_resp_signature_iht;
static int hf_appneta_resp_signature_burst_len;
static int hf_appneta_resp_public_ip;
static int hf_appneta_resp_public_ip_addr;
static int hf_appneta_resp_public_ipv6;
static int hf_appneta_resp_public_ipv6_addr;

/* RTP header fields                                 */
/* Assumptions about RTP: no padding, no extensions, */
/* and no CSRC identifiers (i.e. 12 bytes only)      */
static int hf_rtp_version;
static int hf_rtp_padding;
static int hf_rtp_extension;
static int hf_rtp_csrc_count;
static int hf_rtp_marker;
static int hf_rtp_seq_nr;
static int hf_rtp_timestamp;
static int hf_rtp_ssrc;

/* Initialize the subtree pointers */
static int ett_appneta_resp;
static int ett_appneta_resp_rtp;
static int ett_appneta_resp_seq;
static int ett_appneta_resp_custom;
static int ett_appneta_resp_request;
static int ett_appneta_resp_reply;
static int ett_appneta_resp_flow_create;
static int ett_appneta_resp_flow_response;
static int ett_appneta_resp_flow_close;
static int ett_appneta_resp_test_weight;
static int ett_appneta_resp_test_parameters;
static int ett_appneta_resp_flow_not_found;
static int ett_appneta_resp_burst_info;
static int ett_appneta_resp_responder_version;
static int ett_appneta_resp_outbound_arrival;
static int ett_appneta_resp_burst_hold_time;
static int ett_appneta_resp_outbound_arrival_times;
static int ett_appneta_resp_lost_pkts;
static int ett_appneta_resp_sipport;
static int ett_appneta_resp_protocol;
static int ett_appneta_resp_controlled_burst;
static int ett_appneta_resp_controlled_burst_response;
static int ett_appneta_resp_inboundpacketattr;
static int ett_appneta_resp_h323port;
static int ett_appneta_resp_appliance_type;
static int ett_appneta_resp_error;
static int ett_appneta_resp_controlled_burst_request;
static int ett_appneta_resp_controlled_burst_ready;
static int ett_appneta_resp_enhanced_controlled_burst_request;
static int ett_appneta_resp_enhanced_controlled_burst_response;
static int ett_appneta_resp_signature;
static int ett_appneta_resp_pseudo_cksum;
static int ett_appneta_resp_iface_info;
static int ett_appneta_resp_public_ip_addr;
static int ett_appneta_resp_invalid;

/* Setup protocol subtree array */
static int *ett_resp[] = {
    &ett_appneta_resp,
    &ett_appneta_resp_rtp,
    &ett_appneta_resp_seq,
    &ett_appneta_resp_custom,
    &ett_appneta_resp_reply,
    &ett_appneta_resp_flow_create,
    &ett_appneta_resp_flow_response,
    &ett_appneta_resp_flow_close,
    &ett_appneta_resp_test_weight,
    &ett_appneta_resp_test_parameters,
    &ett_appneta_resp_burst_info,
    &ett_appneta_resp_responder_version,
    &ett_appneta_resp_outbound_arrival,
    &ett_appneta_resp_burst_hold_time,
    &ett_appneta_resp_outbound_arrival_times,
    &ett_appneta_resp_lost_pkts,
    &ett_appneta_resp_sipport,
    &ett_appneta_resp_protocol,
    &ett_appneta_resp_controlled_burst,
    &ett_appneta_resp_controlled_burst_response,
    &ett_appneta_resp_inboundpacketattr,
    &ett_appneta_resp_h323port,
    &ett_appneta_resp_appliance_type,
    &ett_appneta_resp_error,
    &ett_appneta_resp_controlled_burst_request,
    &ett_appneta_resp_controlled_burst_ready,
    &ett_appneta_resp_enhanced_controlled_burst_request,
    &ett_appneta_resp_enhanced_controlled_burst_response,
    &ett_appneta_resp_signature,
    &ett_appneta_resp_pseudo_cksum,
    &ett_appneta_resp_iface_info,
    &ett_appneta_resp_public_ip_addr,
    &ett_appneta_resp_invalid,
};

/*
 * an array of pointers to the subtree index and pointer values to the
 * structure below.  NULL means don't print
 */
static int *hf_subtrees[] = {
    NULL,
    NULL,                                                 /* HDR_LAST */
    &ett_appneta_resp_seq,                                /* HDR_SEQUENCE */
    &ett_appneta_resp_custom,                             /* HDR_CUSTOM_TYPE */
    &ett_appneta_resp_request,                            /* HDR_REQUEST */
    &ett_appneta_resp_reply,                              /* HDR_REPLY */
    &ett_appneta_resp_flow_create,                        /* HDR_FLOW_CREATE */
    &ett_appneta_resp_flow_response,                      /* HDR_FLOW_RESPONSE */
    &ett_appneta_resp_flow_close,                         /* HDR_FLOW_CLOSE */
    &ett_appneta_resp_test_weight,                        /* HDR_TEST_WEIGHT */
    &ett_appneta_resp_test_parameters,                    /* HDR_TEST_PARAMS */
    &ett_appneta_resp_flow_not_found,                     /* HDR_FLOW_PACKET */
    &ett_appneta_resp_burst_info,                         /* HDR_COMMAND_INFO */
    &ett_appneta_resp_responder_version,                  /* HDR_RESPONDERVERSION */
    &ett_appneta_resp_outbound_arrival,                   /* HDR_OUTBOUNDARRIVAL */
    &ett_appneta_resp_burst_hold_time,                    /* HDR_RESPONDERHOLDTIME */
    &ett_appneta_resp_outbound_arrival_times,             /* HDR_OUTBOUNDARRIVALTIME */
    &ett_appneta_resp_lost_pkts,                          /* HDR_LOST_PACKETS */
    &ett_appneta_resp_sipport,                            /* HDR_SIPPORT */
    &ett_appneta_resp_protocol,                           /* HDR_PROTOCOL */
    &ett_appneta_resp_controlled_burst,                   /* HDR_CONTROLLEDBURST */
    &ett_appneta_resp_controlled_burst_response,          /* HDR_CONTROLLEDBURSTRESPONSE */
    &ett_appneta_resp_inboundpacketattr,                  /* HDR_INBOUNDPACKETATTR */
    &ett_appneta_resp_h323port,                           /* HDR_H323PORT */
    &ett_appneta_resp_appliance_type,                     /* HDR_APPLIANCE_TYPE */
    &ett_appneta_resp_error,                              /* HDR_ERROR */
    &ett_appneta_resp_controlled_burst_request,           /* HDR_CONTROLLEDBURSTREQUEST */
    &ett_appneta_resp_controlled_burst_ready,             /* HDR_CONTROLLEDBURSTREADY */
    &ett_appneta_resp_enhanced_controlled_burst_request,  /* HDR_ECBREQUEST */
    &ett_appneta_resp_enhanced_controlled_burst_response, /* HDR_ECBRESPONSE */
    &ett_appneta_resp_signature,                          /* HDR_SIGNATURE */
    &ett_appneta_resp_pseudo_cksum,                       /* HDR_PSEUDO_CKSUM */
    &ett_appneta_resp_iface_info,                         /* HDR_IFACE_INFO */
    &ett_appneta_resp_public_ip_addr,                     /* HDR_PUBLIC_IP_ADDRESS */
    &ett_appneta_resp_invalid,                            /* HDR_RESERVED3 */
    &ett_appneta_resp_invalid,                            /* HDR_RESERVED4 */
    &ett_appneta_resp_invalid,                            /* HDR_RESERVED5 */
    &ett_appneta_resp_invalid,                            /* HDR_RESERVED6 */
    &ett_appneta_resp_invalid,                            /* HDR_RESERVED7 */
    &ett_appneta_resp_invalid,                            /* HDR_RESERVED8 */
    &ett_appneta_resp_invalid,                            /* HDR_RESERVED9 */
    &ett_appneta_resp_invalid,                            /* HDR_INVALID */
    NULL,
    NULL,
};

/*
 * descriptions corresponding to the above subree
 */
static const value_string appneta_resp_header_type_vals[] = {
    { 1,  "No more headers"                    },
    { 2,  "Sequence"                           },
    { 3,  "Custom Type"                        },
    { 4,  "Request"                            },
    { 5,  "Reply"                              },
    { 6,  "Create Flow"                        },
    { 7,  "Flow Response"                      },
    { 8,  "Close Flow"                         },
    { 9,  "Test Weight"                        },
    { 10, "Test Parameters"                    },
    { 11, "Flow not found"                     },
    { 12, "Command Info"                       },
    { 13, "Responder Version"                  },
    { 14, "Outbound Arrival Bits"              },
    { 15, "Responder Hold Time"                },
    { 16, "Outbound Arrival Times"             },
    { 17, "Lost Packets"                       },
    { 18, "Sip Port"                           },
    { 19, "Protocol"                           },
    { 20, "Controlled Burst"                   },
    { 21, "Controlled Burst Response"          },
    { 22, "Inbound Packet Attributes"          },
    { 23, "H.323"                              },
    { 24, "Device Type"                        },
    { 25, "Error"                              },
    { 26, "Controlled Burst Request"           },
    { 27, "Controlled Burst Ready"             },
    { 28, "Enhanced Controlled Burst"          },
    { 29, "Enhanced Controlled Burst Response" },
    { 30, "Signature Header"                   },
    { 31, "Pseudo Checksum"                    },
    { 32, "Interface Info"                     },
    { 33, "Public IP Address"                  },
    { 34, "Reserved 3"                         },
    { 35, "Reserved 4"                         },
    { 36, "Reserved 5"                         },
    { 37, "Reserved 6"                         },
    { 38, "Reserved 7"                         },
    { 39, "Reserved 8"                         },
    { 40, "Reserved 9"                         },
    { 41, "Invalid Header"                     },
    { 0,  NULL                                 },
};

enum ResponderHeaderType {
    HDR_LAST = 1,
    HDR_SEQUENCE,
    HDR_CUSTOM_TYPE,
    HDR_REQUEST,
    HDR_REPLY, /* 5 */
    HDR_FLOW_CREATE,
    HDR_FLOW_RESPONSE,
    HDR_FLOW_CLOSE,
    HDR_TEST_WEIGHT,
    HDR_TEST_PARAMS, /* 10 */
    HDR_FLOW_PACKET, /* not actually a header, used to report flow not found */
    HDR_COMMAND_INFO,
    HDR_RESPONDERVERSION,
    HDR_OUTBOUNDARRIVAL,
    HDR_RESPONDERHOLDTIME, /* 15 */
    HDR_OUTBOUNDARRIVALTIME,
    HDR_LOST_PACKETS,
    HDR_SIPPORT,
    HDR_PROTOCOL,
    HDR_CONTROLLEDBURST, /* 20 */
    HDR_CONTROLLEDBURSTRESPONSE,
    HDR_INBOUNDPACKETATTR,
    HDR_H323PORT,
    HDR_APPLIANCE_TYPE,
    HDR_ERROR, /* 25 */
    HDR_CONTROLLEDBURSTREQUEST,
    HDR_CONTROLLEDBURSTREADY,
    HDR_ECBREQUEST,
    HDR_ECBRESPONSE,
    HDR_SIGNATURE, /* 30 */
    HDR_PSEUDO_CKSUM,
    HDR_IFACE_INFO,
    HDR_PUBLIC_IP_ADDRESS,
    HDR_RESERVED34,
    HDR_RESERVED35,
    HDR_RESERVED36,
    HDR_RESERVED37,
    HDR_RESERVED38,
    HDR_RESERVED39,
    HDR_RESERVED40, /* 40 */
    HDR_INVALID,
    HDR_COUNT,
} ResponderHeaderType;

/* strings to make protocol parsing more readable */
static const value_string rtp_version_vals[] = {
    { 0, "Old VAT Version"     },
    { 1, "First Draft Version" },
    { 2, "RFC 1889 Version"    },
    { 0, NULL                  },
};

/** Struct for boolean representation */
typedef struct true_false_string {
    const char *true_string;  /**< The string presented when true  */
    const char *false_string; /**< The string presented when false */
} true_false_string;

static const true_false_string appneta_tf_set_not_set = {
    "Set",
    "Not Set"
};

static const value_string appneta_resp_error_code_vals[] = {
    { 0,  "Success"                     },
    { 1,  "QoS disabled"                },
    { 2,  "Unknown header"              },
    { 3,  "Option not supported"        },
    { 4,  "Administratively Prohibited" },
    { 5,  "Must set DF"                 },
    { 6,  "UDP checksum not supported"  },
    { 7,  "Internal error"              },
    { 8,  "Unknown flow"                },
    { 9,  "Count error"                 },
    { 10, "QoS lock unavailable"        },
    { 11, "SIP port unavailable"        },
    { 12, "QoS altered"                 },
    { 0,  NULL                          }
};

static const value_string appneta_resp_cmd_type_vals[] = {
    { 0,    "Invalid"                      },
    { 1,    "Burst"                        },
    { 2,    "Datagram"                     },
    { 3,    "Controlled Burst"             },
    { 4,    "Tight Datagram"               },
    { 5,    "Burst Load"                   },
    { 6,    "Enhanced Controlled Burst"    },
    { 0,    "Invalid"                      },
    { 0x81, "Burst with Primer"            },
    { 0x82, "Datagram with Primer"         },
    { 0x83, "Controlled Burst with Primer" },
    { 0x84, "Tight Datagram with Primer"   },
    { 0x85, "Burst Load with Primer"       },
    { 0x86, "Controlled Burst with Primer" },
    { 0,    NULL                           }
};

static const value_string appneta_resp_appliance_type_vals[] = {
    { 0,  "Invalid"           },
    { 1,  "Windows"           },
    { 2,  "Linux 32-bit"      },
    { 3,  "HP UX"             },
    { 4,  "Mac"               },
    { 5,  "iOS"               },
    { 6,  "Solaris Intel"     },
    { 7,  "Solaris SPARC"     },
    { 8,  "m20 appliance"     },
    { 9,  "m22 appliance"     },
    { 10, "m30 appliance"     },
    { 11, "r40 appliance"     },
    { 12, "r400 appliance"    },
    { 13, "virtual appliance" },
    { 14, "v30 appliance"     },
    { 15, "Polycom HDX"       },
    { 16, "Custom"            },
    { 17, "Linux"             },
    { 18, "m25 appliance"     },
    { 19, "m35 appliance"     },
    { 20, "r45 appliance"     },
    { 21, "r450 appliance"    },
    { 22, "vk35 appliance"    },
    { 23, "vk25 appliance"    },
    { 24, "wv00 appliance"    },
    { 25, "Unknown"           },
    { 26, "Unknown"           },
    { 27, "Unknown"           },
    { 28, "Unknown"           },
    { 29, "Unknown"           },
    { 30, "Unknown"           },
    { 31, "Unknown"           },
    { 32, "Unknown"           },
    { 33, "Unknown"           },
    { 0,  NULL                }
};

static dissector_handle_t appneta_responder_handle;
static dissector_handle_t ip_handle;
static dissector_handle_t ip6_handle;
static dissector_handle_t appneta_payload_handle;
static module_t          *proto_reg_appneta_payload;

/* AppNeta Payload */
static int proto_appneta_payload;
static int hf_payload_data;
static int hf_payload_legacy_signature;
static int hf_payload_legacy_corrupt_signature;
static int hf_payload_path_signature;
static int hf_payload_path_reply_signature;
static int hf_payload_path_flags;
static int hf_payload_path_flags_first;
static int hf_payload_path_flags_last;
static int hf_payload_path_flags_iht;
static int hf_payload_path_flags_ext;
static int hf_payload_path_burst_length;
static int hf_payload_path_iht_value;
static int hf_payload_pathtest_signature;
static int hf_payload_pathtest_burst_packets;
static int hf_payload_pathtest_sequence;
static int hf_payload_pathtest_stream;
static int hf_payload_data_len;

static int ett_payload;
static int ett_data;
static int ett_flags;

/*
 * Fields in the first octet of the RTP header.
 */

/* Version is the first 2 bits of the first octet*/
#define RTP_VERSION(octet) ((octet) >> 6)

/* Padding is the third bit; No need to shift, because true is any value
other than 0! */
#define RTP_PADDING(octet) ((octet) & 0x20)

/* Extension bit is the fourth bit */
#define RTP_EXTENSION(octet) ((octet) & 0x10)

/* CSRC count is the last four bits */
#define RTP_CSRC_COUNT(octet) ((octet) & 0xF)

/*
 * Fields in the second octet of the RTP header.
 */

/* Marker is the first bit of the second octet */
#define RTP_MARKER(octet) ((octet) & 0x80)

/* Payload type is the last 7 bits */
#define RTP_PAYLOAD_TYPE(octet) ((octet) & 0x7F)

/*******************************************************************/
/* Parse the RTP header and return the number of bytes processed.
 * If appneta_resp_tree is set to NULL just return the length of
 * the header; otherwise add items to the dissector tree.
 */
static int
dissect_rtp_header(tvbuff_t *tvb, const packet_info *pinfo _U_, int offset,
        proto_tree *appneta_resp_tree, gboolean get_len_only)
{
    proto_tree *rtp_tree = NULL;

    /* Get the fields in the first octet */
    uint8_t octet1 = tvb_get_uint8(tvb, offset);
    uint8_t octet2 = tvb_get_uint8(tvb, offset + 1);

    if (octet1 != 0x80 || (octet2 & 0x7F) != 0x02) {
        /* this is not an RTP header, so return 0 bytes processed */
        return 0;
    }

    /* Get the fields in the second octet */
    if (get_len_only) {
        /* just return the length without adding items to the dissector tree */
        return RTP_HEADER_LENGTH;
    }

    char *path_type = RTP_MARKER(octet2) ? " Dual-ended" : " Single-ended";
    col_append_str(pinfo->cinfo, COL_INFO, path_type);

    /* Get the subsequent fields */
    uint16_t seq_num   = tvb_get_ntohs(tvb, offset + 2);
    uint32_t timestamp = tvb_get_ntohl(tvb, offset + 4);
    uint32_t sync_src  = tvb_get_ntohl(tvb, offset + 8);

    /* Create a subtree for RTP */
    if (sync_src == NO_FLOW) {
        rtp_tree = proto_tree_add_subtree_format(appneta_resp_tree, tvb, offset, RTP_HEADER_LENGTH, ett_appneta_resp_rtp, NULL,
                "Responder RTP Header: No flow, %s", path_type);
    } else {
        rtp_tree = proto_tree_add_subtree_format(appneta_resp_tree, tvb, offset, RTP_HEADER_LENGTH, ett_appneta_resp_rtp, NULL,
                "Responder RTP Header: Flow %u, %s", sync_src, path_type);
        col_append_fstr(pinfo->cinfo, COL_INFO, " Flow=%u", sync_src);
    }

    /* Add items to the RTP subtree */
    proto_tree_add_uint(rtp_tree, hf_rtp_version, tvb, offset, 1, octet1);
    proto_tree_add_boolean(rtp_tree, hf_rtp_padding, tvb, offset, 1, octet1);
    proto_tree_add_boolean(rtp_tree, hf_rtp_extension, tvb, offset, 1, octet1);
    proto_tree_add_uint(rtp_tree, hf_rtp_csrc_count, tvb, offset, 1, octet1);
    offset++;

    proto_tree_add_boolean(rtp_tree, hf_rtp_marker, tvb, offset, 1, octet2);
    offset++;

    /* Sequence number 16 bits (2 octets) */
    proto_tree_add_uint(rtp_tree, hf_rtp_seq_nr, tvb, offset, 2, seq_num);
    offset += 2;

    /* Timestamp 32 bits (4 octets) */
    proto_tree_add_uint(rtp_tree, hf_rtp_timestamp, tvb, offset, 4, timestamp);
    offset += 4;

    /* Synchronization source identifier 32 bits (4 octets) */
    proto_tree_add_uint(rtp_tree, hf_rtp_ssrc, tvb, offset, 4, sync_src);
    offset += 4;

    return offset;
}

static proto_tree *
add_subtree(tvbuff_t *tvb, int *offset, proto_tree *current_tree,
        int header, uint8_t headerLength, const char *title)
{
    proto_tree *tree = NULL;

    if (current_tree && header < HDR_COUNT && hf_subtrees[header]) {
        tree = proto_tree_add_subtree(current_tree, tvb, *offset, headerLength,
                *(hf_subtrees[header]), NULL, title);
    }

    if (tree) {
        proto_tree_add_item(tree, hf_appneta_resp_next_header_type, tvb, *offset, 1, ENC_NA);
        proto_tree_add_item(tree, hf_appneta_resp_header_length, tvb, *offset + 1, 1, ENC_NA);
    }

    *offset += 2;

    return tree;
}

/*******************************************************************/
/* Parse the responder header starting at the offset in the tvb
 * buffer.  If appneta_resp_tree is set to NULL just return the length of
 * the header; otherwise add items to the dissector tree.
 */
static int
dissect_responder_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *appneta_resp_tree, void *data)
{
    int      currentHeader, nextHeader;
    uint8_t  headerLength = 0, mode = 0;
    uint8_t  flags  = 0;
    int      offset = 0;
    uint32_t id, flow, major, minor, revision, build, first_id = 0,
                                                      burst_hold_time, i, depth;
    uint32_t cb_in_count  = 0,
             cb_in_gap    = 0,
             cb_out_count = 0,
             cb_out_gap   = 0,
             cb_in_flags  = 0;
    uint16_t           port, portend, weight, burstsize = 0;
    proto_tree        *current_tree = NULL, *field_tree = NULL;
    proto_item        *tf = NULL;
    tvbuff_t          *next_tvb;
    gboolean           save_in_error_pkt;
    int                remaining        = tvb_captured_length_remaining(tvb, 0);
    appneta_pkt_type_t appneta_pkt_type = APPNETA_PACKET_TYPE_UNDEFINED;
    uint32_t           pass             = 0;

    if (data && strcmp((const char *)data, "ani-payload") == 0) {
        currentHeader    = HDR_SIGNATURE;
        appneta_pkt_type = APPNETA_PACKET_TYPE_PATH;
    } else if (data && strcmp((const char *)data, "ani-reply-payload") == 0) {
        currentHeader    = HDR_SIGNATURE;
        appneta_pkt_type = APPNETA_PACKET_TYPE_PATH_REPLY;
    } else {
        currentHeader = HDR_SEQUENCE;
    }

    while (currentHeader != HDR_LAST && currentHeader < HDR_INVALID) {
        current_tree = appneta_resp_tree;
        nextHeader   = tvb_get_uint8(tvb, offset);
        headerLength = tvb_get_uint8(tvb, offset + 1);

        if (offset > remaining || pass++ > 50) {
            g_print("dissect_responder_header: opps: offset=%d remaining=%d pass=%d\n",
                    offset, remaining, pass);
            return 0;
        }

        switch (currentHeader) {
            case HDR_SEQUENCE:
                current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
                        "Sequence Header");
                id           = tvb_get_ntohl(tvb, offset);
                proto_tree_add_item(current_tree, hf_appneta_resp_pkt_id, tvb, offset, 4, ENC_NA);

                /* set some text in the info column */
                col_append_fstr(pinfo->cinfo, COL_INFO, " ID=%u", id);
                break;
            case HDR_ERROR:
                current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
                        "Error Header");
                proto_tree_add_item(current_tree, hf_appneta_resp_error_code, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(current_tree, hf_appneta_resp_error_value, tvb, offset + 1, 1, ENC_NA);

                /* set some text in the info column */
                col_append_str(pinfo->cinfo, COL_INFO, " [Contains Errors]");
                break;
            case HDR_REQUEST:
                current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
                        "Request Header");
                break;
            case HDR_REPLY:
                if (tvb_captured_length(tvb) >= 28 && ip_handle) {
                    uint8_t version;

                    version      = tvb_get_uint8(tvb, offset + 2) >> 4;
                    current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
                            "Reply Header");
                    /* Save the current value of the "we're inside an error packet"
                     * flag, and set that flag; subdissectors may treat packets
                     * that are the payload of error packets differently from
                     * "real" packets.
                     */
                    save_in_error_pkt         = pinfo->flags.in_error_pkt;
                    pinfo->flags.in_error_pkt = TRUE;

                    next_tvb = tvb_new_subset_remaining(tvb, offset);
                    if (version == 4) {
                        /* the next 28 bytes are the ipv4 and udp headers to be used in the response */
                        set_actual_length(next_tvb, 28);
                        call_dissector(ip_handle, next_tvb, pinfo, current_tree);
                    } else if (version == 6 && tvb_captured_length(next_tvb) >= 48 && ip6_handle) {
                        /* the next 48 bytes are the ipv6 and udp headers to be used in the response */
                        set_actual_length(next_tvb, 48);
                        call_dissector(ip6_handle, next_tvb, pinfo, current_tree);
                    } else {
                        save_in_error_pkt = TRUE;
                    }

                    /* Restore the "we're inside an error packet" flag. */
                    pinfo->flags.in_error_pkt = save_in_error_pkt;
                }
                break;
            case HDR_FLOW_CREATE:
                current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
                        "Create Flow Header");
                port         = tvb_get_ntohs(tvb, offset);
                if (headerLength >= 6) {
                    proto_tree_add_item(current_tree, hf_appneta_resp_flow_port_first, tvb, offset, 2, ENC_NA);
                    proto_tree_add_item(current_tree, hf_appneta_resp_flow_port_last, tvb, offset + 2, 2, ENC_NA);
                } else {
                    proto_tree_add_item(current_tree, hf_appneta_resp_flow_port, tvb, offset, 2, ENC_NA);
                }

                /* set some text in the info column */
                if (headerLength >= 6) {
                    portend = tvb_get_ntohs(tvb, offset + 2);
                    col_append_fstr(pinfo->cinfo, COL_INFO, " Create Flows (ports %d through %d)", port, portend);
                } else {
                    col_append_fstr(pinfo->cinfo, COL_INFO, " Create Flow (port %d)", port);
                }
                break;
            case HDR_FLOW_RESPONSE:
                current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
                        "Reply Header");
                flow         = tvb_get_ntohl(tvb, offset);
                port         = tvb_get_ntohs(tvb, offset + 4);
                proto_tree_add_item(current_tree, hf_appneta_resp_flow_num, tvb, offset, 4, ENC_NA);
                proto_tree_add_item(current_tree, hf_appneta_resp_flow_port, tvb, offset + 4, 2, ENC_NA);
                proto_tree_add_item(current_tree, hf_appneta_resp_response_status, tvb, offset + 6, 2, ENC_NA);

                /* tell Wireshark to dissect packets addressed to hf_appneta_resp_flow_port
                 * using this dissector.
                 */
                if (port != UDP_PORT_APPNETA_RESP)
                    dissector_add_uint("udp.port", port, appneta_responder_handle);

                /* set some text in the info column */
                col_append_fstr(pinfo->cinfo, COL_INFO, " Flow Response: Flow ID=%u", flow);
                break;
            case HDR_FLOW_CLOSE:
                current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
                        "Close Flow Header");
                flow         = tvb_get_ntohl(tvb, offset);
                proto_tree_add_item(current_tree, hf_appneta_resp_flow_num, tvb, offset, 4, ENC_NA);
                proto_tree_add_item(current_tree, hf_appneta_resp_flow_port, tvb, offset + 4, 2, ENC_NA);
                proto_tree_add_item(current_tree, hf_appneta_resp_response_status, tvb, offset + 6, 2, ENC_NA);

                /* set some text in the info column */
                col_append_fstr(pinfo->cinfo, COL_INFO, " Close Flow: Flow ID=%u", flow);
                break;
            case HDR_TEST_WEIGHT:
                current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
                        "Test Weight Header");
                weight       = tvb_get_ntohs(tvb, offset);
                proto_tree_add_item(current_tree, hf_appneta_resp_test_weight, tvb, offset, 2, ENC_NA);

                /* set some text in the info column */
                col_append_fstr(pinfo->cinfo, COL_INFO, " Weight=%d", weight);
                break;
            case HDR_RESPONDERVERSION:
                current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
                        "Responder Version Header");
                major        = tvb_get_ntohl(tvb, offset);
                minor        = tvb_get_ntohl(tvb, offset + 4);
                revision     = tvb_get_ntohl(tvb, offset + 8);
                build        = tvb_get_ntohl(tvb, offset + 12);
                proto_tree_add_item(current_tree, hf_appneta_resp_responder_version_major, tvb, offset, 4, ENC_NA);
                proto_tree_add_item(current_tree, hf_appneta_resp_responder_version_minor, tvb, offset + 4, 4, ENC_NA);
                proto_tree_add_item(current_tree, hf_appneta_resp_responder_version_revision, tvb, offset + 8, 4, ENC_NA);
                proto_tree_add_item(current_tree, hf_appneta_resp_responder_version_build, tvb, offset + 12, 4, ENC_NA);

                /* set some text in the info column */
                col_append_fstr(pinfo->cinfo, COL_INFO, " Version=%d.%d.%d.%d", major, minor, revision, build);
                break;
            case HDR_COMMAND_INFO:
                current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
                        "Command Info Header");
                first_id     = tvb_get_ntohl(tvb, offset);
                burstsize    = tvb_get_ntohs(tvb, offset + 4);
                proto_tree_add_item(current_tree, hf_appneta_resp_first_id, tvb, offset, 4, ENC_NA);
                proto_tree_add_item(current_tree, hf_appneta_resp_burst_size, tvb, offset + 4, 2, ENC_NA);
                if (headerLength > 8) {
                    proto_tree_add_item(current_tree, hf_appneta_resp_packet_size, tvb, offset + 6, 2, ENC_NA);
                }
                if (headerLength >= 11) {
                    proto_tree_add_item(current_tree, hf_appneta_resp_command_type, tvb, offset + 8, 1, ENC_NA);
                    mode = tvb_get_uint8(tvb, offset + 8);
                }
                if (headerLength >= 12) {
                    flags      = tvb_get_uint8(tvb, offset + 9);
                    tf         = proto_tree_add_uint(current_tree, hf_appneta_resp_command_flags, tvb, offset + 9, 1, flags);
                    field_tree = proto_item_add_subtree(tf, ett_appneta_resp_burst_info);
                    proto_tree_add_boolean(field_tree, hf_appneta_resp_command_flags_is_inbound, tvb, offset + 9, 1, flags);
                    proto_tree_add_boolean(field_tree, hf_appneta_resp_command_flags_is_super_jumbo, tvb, offset + 9, 1, flags);
                    proto_tree_add_boolean(field_tree, hf_appneta_resp_command_flags_is_jumbo, tvb, offset + 9, 1, flags);
                }

                /* set some text in the info column */
                if (mode == 1) {
                    col_append_fstr(pinfo->cinfo, COL_INFO, " Burst");
                } else if (mode == 2) {
                    col_append_fstr(pinfo->cinfo, COL_INFO, " Datagram");
                } else if (mode == 3) {
                    if ((flags & 0x4)) {
                        col_append_fstr(pinfo->cinfo, COL_INFO, " Controlled Burst Response");
                    } else {
                        col_append_fstr(pinfo->cinfo, COL_INFO, " Controlled Burst");
                    }
                } else if (mode == 4) {
                    col_append_fstr(pinfo->cinfo, COL_INFO, " Tight Dgrm");
                } else if (mode == 5) {
                    col_append_fstr(pinfo->cinfo, COL_INFO, " Burst Load");
                } else if (mode == 0x81) {
                    col_append_fstr(pinfo->cinfo, COL_INFO, " Burst (Primer)");
                } else if (mode == 0x82) {
                    col_append_fstr(pinfo->cinfo, COL_INFO, " Datagram (Primer)");
                } else if (mode == 0x83) {
                    col_append_fstr(pinfo->cinfo, COL_INFO, " Controlled Burst (Primer)");
                } else if (mode == 0x84) {
                    col_append_fstr(pinfo->cinfo, COL_INFO, " Tight Dgrm (Primer)");
                } else if (mode == 0x85) {
                    col_append_fstr(pinfo->cinfo, COL_INFO, " Burst Load (Primer)");
                }
                col_append_fstr(pinfo->cinfo, COL_INFO, " First ID=%d Packets=%d", first_id, burstsize);
                break;
            case HDR_OUTBOUNDARRIVAL:
                current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
                        "Outbound Arrival Bits");
                proto_tree_add_item(current_tree, hf_appneta_resp_outbound_arrival_bits, tvb, offset, 8, ENC_NA);

                /* set some text in the info column */
                col_append_fstr(pinfo->cinfo, COL_INFO, " Response");
                break;
            case HDR_RESPONDERHOLDTIME:
                current_tree    = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
                           "Responder Hold Times");
                burst_hold_time = tvb_get_ntohl(tvb, offset);
                proto_tree_add_item(current_tree, hf_appneta_resp_burst_hold_time_us, tvb, offset, 4, ENC_NA);

                /* set some text in the info column */
                col_append_fstr(pinfo->cinfo, COL_INFO, " RHT=%u usec", burst_hold_time);
                break;
            case HDR_OUTBOUNDARRIVALTIME:
                current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
                        "Outbound Arrival Timestamps");
                i            = 0;
                depth        = headerLength - 2;
                for (; i < depth; i += 4) {
                    proto_tree_add_item(current_tree, hf_appneta_resp_outbound_arrival_times, tvb, offset + i, 4, ENC_NA);
                }
                break;
            case HDR_LOST_PACKETS:
                current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
                        "Lost Packets");
                depth        = headerLength - 2;
                for (i = 0; i < depth; i += 4) {
                    proto_tree_add_item(current_tree, hf_appneta_resp_lost_id, tvb, offset + i, 4, ENC_NA);
                }
                col_append_fstr(pinfo->cinfo, COL_INFO, " Loss");
                break;
            case HDR_SIPPORT:
                {
                    current_tree      = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
                                 "Sip Port");
                    uint32_t idLength = headerLength - 4;
                    proto_tree_add_item(current_tree, hf_appneta_resp_sipport, tvb, offset, 2, ENC_NA);
                    proto_tree_add_item(current_tree, hf_appneta_resp_ta_id, tvb, offset + 2, idLength, ENC_ASCII);
                    break;
                }
            case HDR_PROTOCOL:
                current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
                        "Protocol");
                proto_tree_add_item(current_tree, hf_appneta_resp_protocol, tvb, offset, 4, ENC_NA);
                break;
            case HDR_CONTROLLEDBURST:
                current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
                        "Controlled Burst ");
                cb_in_count  = tvb_get_ntohl(tvb, offset);
                cb_in_gap    = tvb_get_ntohl(tvb, offset + 4);
                cb_in_flags  = cb_in_count & 0x80000000;
                proto_tree_add_boolean(current_tree, hf_appneta_resp_cb_inbound_flags_csv_debug, tvb, offset, 4, cb_in_flags);
                proto_tree_add_uint(current_tree, hf_appneta_resp_cb_inbound_packetcount, tvb, offset, 4, cb_in_count & 0x7fffffff);
                proto_tree_add_uint(current_tree, hf_appneta_resp_cb_inbound_interpacketgap, tvb, offset + 4, 4, cb_in_gap);
                if (cb_in_flags) {
                    col_append_fstr(pinfo->cinfo, COL_INFO, "Debug ");
                }
                if (headerLength >= 18) {
                    cb_out_count = tvb_get_ntohl(tvb, offset + 8);
                    cb_out_gap   = tvb_get_ntohl(tvb, offset + 12);
                    proto_tree_add_uint(current_tree, hf_appneta_resp_cb_outbound_packetcount, tvb, offset + 8, 4, cb_out_count);
                    proto_tree_add_uint(current_tree, hf_appneta_resp_cb_outbound_interpacketgap, tvb, offset + 12, 4, cb_out_gap);
                    col_append_fstr(pinfo->cinfo, COL_INFO, "Out=%d/%d In=%d/%d (pkts/gap)",
                            cb_out_count, cb_out_gap, cb_in_count & 0x7fffffff, cb_in_gap);
                } else {
                    col_append_fstr(pinfo->cinfo, COL_INFO, "%d/%d (pkts/gap)", cb_in_count & 0x7fffffff, cb_in_gap);
                }
                break;
            case HDR_CONTROLLEDBURSTRESPONSE:
                current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
                        "Controlled Burst Response");
                proto_tree_add_item(current_tree, hf_appneta_resp_cb_resp_ratelimitcbrate, tvb, offset, 4, ENC_NA);
                proto_tree_add_item(current_tree, hf_appneta_resp_cb_resp_minpacketcount, tvb, offset + 4, 4, ENC_NA);
                break;
            case HDR_INBOUNDPACKETATTR:
                current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
                        "Inbound Packet Attributes");
                proto_tree_add_item(current_tree, hf_appneta_resp_inboundpacketcount, tvb, offset, 2, ENC_NA);
                proto_tree_add_item(current_tree, hf_appneta_resp_inboundpacketsize, tvb, offset + 2, 2, ENC_NA);
                burstsize = tvb_get_ntohs(tvb, offset);
                col_append_fstr(pinfo->cinfo, COL_INFO, "/%d (out/in)", burstsize);
                break;
            case HDR_H323PORT:
                current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
                        "H.323");
                proto_tree_add_item(current_tree, hf_appneta_resp_h323port, tvb, offset, 2, ENC_NA);
                break;
            case HDR_APPLIANCE_TYPE:
                current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
                        "Device Type");
                proto_tree_add_item(current_tree, hf_appneta_resp_appliance_type, tvb, offset, 1, ENC_NA);
                break;
            case HDR_CUSTOM_TYPE:
                current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
                        "Custom Type");
                proto_tree_add_item(current_tree, hf_appneta_resp_custom_appliance_type, tvb, offset, headerLength - 2, ENC_ASCII);
                break;
            case HDR_CONTROLLEDBURSTREADY:
                col_append_fstr(pinfo->cinfo, COL_INFO, " Controlled Burst Ready");
                current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
                        "Controlled Burst Ready");
                proto_tree_add_item(current_tree, hf_appneta_resp_cb_ready_reserved1, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(current_tree, hf_appneta_resp_cb_ready_reserved2, tvb, offset + 1, 1, ENC_NA);
                break;
            case HDR_CONTROLLEDBURSTREQUEST:
                col_append_fstr(pinfo->cinfo, COL_INFO, " Controlled Burst Request");
                current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
                        "Controlled Burst Request");
                proto_tree_add_item(current_tree, hf_appneta_resp_cb_request_reserved1, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(current_tree, hf_appneta_resp_cb_request_reserved2, tvb, offset + 1, 1, ENC_NA);
                break;
            case HDR_ECBREQUEST:
                {
                    gboolean first_seq, last_seq, is_reply, is_rx_report_all,
                            is_in_gap_ns, is_out_gap_ns;

                    current_tree     = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
                                "Enhanced Controlled Burst Request");
                    flags            = tvb_get_uint8(tvb, offset + 1);
                    first_seq        = !!(flags & 0x01);
                    last_seq         = !!(flags & 0x02);
                    is_reply         = !!(flags & 0x04);
                    is_rx_report_all = !!(flags & 0x08);
                    is_in_gap_ns     = !!(flags & 0x10);
                    is_out_gap_ns    = !!(flags & 0x20);
                    proto_tree_add_item(current_tree, hf_appneta_resp_ecb_request_padding, tvb, offset, 1, ENC_NA);
                    tf         = proto_tree_add_uint(current_tree, hf_appneta_resp_ecb_request_flags, tvb, offset + 1, 1, flags);
                    field_tree = proto_item_add_subtree(tf, ett_appneta_resp_enhanced_controlled_burst_request);
                    if (is_reply) {
                        proto_item_append_text(tf, " (Reply)");
                        col_append_fstr(pinfo->cinfo, COL_INFO, " Reply");
                    }
                    if (first_seq) {
                        proto_item_append_text(tf, " (First sequence)");
                        col_append_fstr(pinfo->cinfo, COL_INFO, " First Seq");
                    }
                    if (last_seq) {
                        proto_item_append_text(tf, " (Last sequence)");
                        col_append_fstr(pinfo->cinfo, COL_INFO, " Last Seq");
                    }
                    if (is_rx_report_all) {
                        proto_item_append_text(tf, " (RX Report All)");
                        col_append_fstr(pinfo->cinfo, COL_INFO, " Report All");
                    }
                    if (is_in_gap_ns) {
                        proto_item_append_text(tf, " (Inbound Gap NS)");
                        col_append_fstr(pinfo->cinfo, COL_INFO, " IN NS");
                    }
                    if (is_out_gap_ns) {
                        proto_item_append_text(tf, " (Outbound Gap NS)");
                        col_append_fstr(pinfo->cinfo, COL_INFO, " OUT NS");
                    }
                    proto_tree_add_boolean(field_tree, hf_appneta_resp_ecb_request_flags_outbound_gap_ns, tvb, offset + 1, 1, flags);
                    proto_tree_add_boolean(field_tree, hf_appneta_resp_ecb_request_flags_inbound_gap_ns, tvb, offset + 1, 1, flags);
                    proto_tree_add_boolean(field_tree, hf_appneta_resp_ecb_request_flags_rx_report_all, tvb, offset + 1, 1, flags);
                    proto_tree_add_boolean(field_tree, hf_appneta_resp_ecb_request_flags_reply, tvb, offset + 1, 1, flags);
                    proto_tree_add_boolean(field_tree, hf_appneta_resp_ecb_request_flags_last_seq, tvb, offset + 1, 1, flags);
                    proto_tree_add_boolean(field_tree, hf_appneta_resp_ecb_request_flags_first_seq, tvb, offset + 1, 1, flags);
                    proto_tree_add_item(current_tree, hf_appneta_resp_ecb_request_ssn, tvb, offset + 2, 4, ENC_NA);
                    proto_tree_add_item(current_tree, hf_appneta_resp_ecb_request_outbound_magnify, tvb, offset + 6, 2, ENC_NA);
                    col_append_fstr(pinfo->cinfo, COL_INFO, " ECB out[mag=%u", tvb_get_ntohs(tvb, offset + 6));
                    proto_tree_add_item(current_tree, hf_appneta_resp_ecb_request_outbound_duration, tvb, offset + 8, 2, ENC_NA);
                    col_append_fstr(pinfo->cinfo, COL_INFO, " dur=%ums", tvb_get_ntohs(tvb, offset + 8));
                    proto_tree_add_item(current_tree, hf_appneta_resp_ecb_request_outbound_gap, tvb, offset + 10, 2, ENC_NA);
                    col_append_fstr(pinfo->cinfo, COL_INFO, " gap=%uus", tvb_get_ntohs(tvb, offset + 10));
                    if (headerLength > 20) {
                        col_append_fstr(pinfo->cinfo, COL_INFO, " max=%upkts", tvb_get_ntohl(tvb, offset + 18));
                    }
                    col_append_fstr(pinfo->cinfo, COL_INFO, "]");
                    proto_tree_add_item(current_tree, hf_appneta_resp_ecb_request_inbound_magnify, tvb, offset + 12, 2, ENC_NA);
                    col_append_fstr(pinfo->cinfo, COL_INFO, " in[mag=%u", tvb_get_ntohs(tvb, offset + 12));
                    proto_tree_add_item(current_tree, hf_appneta_resp_ecb_request_inbound_duration, tvb, offset + 14, 2, ENC_NA);
                    col_append_fstr(pinfo->cinfo, COL_INFO, " dur=%ums", tvb_get_ntohs(tvb, offset + 14));
                    proto_tree_add_item(current_tree, hf_appneta_resp_ecb_request_inbound_gap, tvb, offset + 16, 2, ENC_NA);
                    col_append_fstr(pinfo->cinfo, COL_INFO, " gap=%uus", tvb_get_ntohs(tvb, offset + 16));
                    if (headerLength > 20) {
                        proto_tree_add_item(current_tree, hf_appneta_resp_ecb_request_outbound_max_packets, tvb, offset + 18, 4, ENC_NA);
                        proto_tree_add_item(current_tree, hf_appneta_resp_ecb_request_inbound_max_packets, tvb, offset + 22, 4, ENC_NA);
                        col_append_fstr(pinfo->cinfo, COL_INFO, " max=%upkts", tvb_get_ntohl(tvb, offset + 22));
                    }
                    col_append_fstr(pinfo->cinfo, COL_INFO, "]");
                    break;
                }
            case HDR_ECBRESPONSE:
                {
                    gboolean out_avail, in_avail, final_results;

                    current_tree  = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
                             "Enhanced Controlled Burst Response");
                    flags         = tvb_get_uint8(tvb, offset + 1);
                    in_avail      = !!(flags & 0x01);
                    out_avail     = !!(flags & 0x02);
                    final_results = !!(flags & 0x04);
                    proto_tree_add_item(current_tree, hf_appneta_resp_ecb_resp_padding, tvb, offset, 1, ENC_NA);
                    tf         = proto_tree_add_uint(current_tree, hf_appneta_resp_ecb_resp_flags, tvb, offset + 1, 1, flags);
                    field_tree = proto_item_add_subtree(tf, ett_appneta_resp_enhanced_controlled_burst_response);
                    proto_tree_add_boolean(field_tree, hf_appneta_resp_ecb_resp_flags_final, tvb, offset + 1, 1, flags);
                    proto_tree_add_boolean(field_tree, hf_appneta_resp_ecb_resp_flags_out, tvb, offset + 1, 1, flags);
                    proto_tree_add_boolean(field_tree, hf_appneta_resp_ecb_resp_flags_in, tvb, offset + 1, 1, flags);
                    proto_tree_add_item(current_tree, hf_appneta_resp_ecb_resp_outbound_first_tx_ts, tvb, offset + 2, 4, ENC_NA);
                    proto_tree_add_item(current_tree, hf_appneta_resp_ecb_resp_outbound_first_rx_ts, tvb, offset + 6, 4, ENC_NA);
                    proto_tree_add_item(current_tree, hf_appneta_resp_ecb_resp_outbound_ll_rx, tvb, offset + 10, 4, ENC_NA);
                    proto_tree_add_item(current_tree, hf_appneta_resp_ecb_resp_outbound_ll_rx_bytes, tvb, offset + 14, 8, ENC_NA);
                    proto_tree_add_item(current_tree, hf_appneta_resp_ecb_resp_outbound_ll_us, tvb, offset + 22, 4, ENC_NA);
                    proto_tree_add_item(current_tree, hf_appneta_resp_ecb_resp_outbound_total_rx, tvb, offset + 26, 4, ENC_NA);
                    proto_tree_add_item(current_tree, hf_appneta_resp_ecb_resp_outbound_total_rx_bytes, tvb, offset + 30, 8, ENC_NA);
                    proto_tree_add_item(current_tree, hf_appneta_resp_ecb_resp_outbound_total_us, tvb, offset + 38, 4, ENC_NA);
                    if (final_results) {
                        proto_item_append_text(tf, " (Final results)");
                        col_append_fstr(pinfo->cinfo, COL_INFO, " Final");
                    }
                    if (out_avail) {
                        proto_item_append_text(tf, " (Out-bound results)");
                        col_append_fstr(pinfo->cinfo, COL_INFO, " RX-out[ll=%u", tvb_get_ntohl(tvb, offset + 10));
                        col_append_fstr(pinfo->cinfo, COL_INFO, "/%uus", tvb_get_ntohl(tvb, offset + 22) - tvb_get_ntohl(tvb, offset + 6));
                        col_append_fstr(pinfo->cinfo, COL_INFO, " total=%u", tvb_get_ntohl(tvb, offset + 26));
                        col_append_fstr(pinfo->cinfo, COL_INFO, "/%uus]", tvb_get_ntohl(tvb, offset + 38) - tvb_get_ntohl(tvb, offset + 6));
                    }
                    proto_tree_add_item(current_tree, hf_appneta_resp_ecb_resp_inbound_first_tx_ts, tvb, offset + 42, 4, ENC_NA);
                    proto_tree_add_item(current_tree, hf_appneta_resp_ecb_resp_inbound_first_rx_ts, tvb, offset + 46, 4, ENC_NA);
                    proto_tree_add_item(current_tree, hf_appneta_resp_ecb_resp_inbound_ll_rx, tvb, offset + 50, 4, ENC_NA);
                    proto_tree_add_item(current_tree, hf_appneta_resp_ecb_resp_inbound_ll_rx_bytes, tvb, offset + 54, 8, ENC_NA);
                    proto_tree_add_item(current_tree, hf_appneta_resp_ecb_resp_inbound_ll_us, tvb, offset + 62, 4, ENC_NA);
                    proto_tree_add_item(current_tree, hf_appneta_resp_ecb_resp_inbound_total_rx, tvb, offset + 66, 4, ENC_NA);
                    proto_tree_add_item(current_tree, hf_appneta_resp_ecb_resp_inbound_total_rx_bytes, tvb, offset + 70, 8, ENC_NA);
                    proto_tree_add_item(current_tree, hf_appneta_resp_ecb_resp_inbound_total_us, tvb, offset + 78, 4, ENC_NA);
                    if (in_avail) {
                        proto_item_append_text(tf, " (In-bound results)");
                        col_append_fstr(pinfo->cinfo, COL_INFO, " RX-in[ll=%u", tvb_get_ntohl(tvb, offset + 50));
                        col_append_fstr(pinfo->cinfo, COL_INFO, "/%uus", tvb_get_ntohl(tvb, offset + 62) - tvb_get_ntohl(tvb, offset + 46));
                        col_append_fstr(pinfo->cinfo, COL_INFO, " total=%u", tvb_get_ntohl(tvb, offset + 66));
                        col_append_fstr(pinfo->cinfo, COL_INFO, "/%uus]", tvb_get_ntohl(tvb, offset + 78) - tvb_get_ntohl(tvb, offset + 46));
                    }
                    break;
                }
            case HDR_SIGNATURE:
                current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
                        "Signature Header");
                if (appneta_pkt_type == APPNETA_PACKET_TYPE_UNDEFINED) {
                    const uint8_t *cp = tvb_get_ptr(tvb, offset,
                            tvb_captured_length_remaining(tvb, offset));

                    if (cp) {
                        if (!memcmp(cp, APPNETA_PAYLOAD_SIGNATURE, sizeof(APPNETA_PAYLOAD_SIGNATURE)))
                            appneta_pkt_type = APPNETA_PACKET_TYPE_PATH;
                        else if (!memcmp(cp, APPNETA_REPLY_PAYLOAD_SIGNATURE, sizeof(APPNETA_REPLY_PAYLOAD_SIGNATURE)))
                            appneta_pkt_type = APPNETA_PACKET_TYPE_PATH_REPLY;
                        else if (!memcmp(cp, APPNETA_LEGACY_PAYLOAD_SIGNATURE, sizeof(APPNETA_LEGACY_PAYLOAD_SIGNATURE)))
                            appneta_pkt_type = APPNETA_PACKET_TYPE_LEGACY;
                        else if (!memcmp(cp, PATHTEST_PAYLOAD_SIGNATURE, sizeof(PATHTEST_PAYLOAD_SIGNATURE)))
                            appneta_pkt_type = APPNETA_PACKET_TYPE_PATHTEST;
                    }
                }

                if (headerLength > 6) {
                    /* this is a dual-ended signature */
                    switch (appneta_pkt_type) {
                        case APPNETA_PACKET_TYPE_PATH:
                            proto_tree_add_item(current_tree, hf_appneta_resp_signature_path, tvb, offset,
                                    sizeof(APPNETA_PAYLOAD_SIGNATURE), ENC_NA);
                            break;
                        case APPNETA_PACKET_TYPE_PATH_REPLY:
                            proto_tree_add_item(current_tree, hf_appneta_resp_signature_path_reply, tvb, offset,
                                    sizeof(APPNETA_REPLY_PAYLOAD_SIGNATURE), ENC_NA);
                            break;
                        case APPNETA_PACKET_TYPE_LEGACY:
                            proto_tree_add_item(current_tree, hf_appneta_resp_signature_legacy, tvb, offset,
                                    sizeof(APPNETA_LEGACY_PAYLOAD_SIGNATURE), ENC_NA);
                            break;
                        case APPNETA_PACKET_TYPE_PATHTEST:
                            proto_tree_add_item(current_tree, hf_appneta_resp_signature_pathtest, tvb, offset,
                                    sizeof(PATHTEST_PAYLOAD_SIGNATURE), ENC_NA);
                            break;
                        default:
                            proto_tree_add_item(current_tree, hf_appneta_resp_signature_undefined,
                                    tvb, offset, sizeof(APPNETA_PAYLOAD_SIGNATURE), ENC_NA);
                    }

                    switch (appneta_pkt_type) {
                        case APPNETA_PACKET_TYPE_PATH:
                        case APPNETA_PACKET_TYPE_PATH_REPLY:
                            flags      = tvb_get_uint8(tvb, offset + 5);
                            tf         = proto_tree_add_uint(current_tree, hf_appneta_resp_signature_flags, tvb, offset + 5, 1, flags);
                            field_tree = proto_item_add_subtree(tf, ett_appneta_resp_signature);
                            proto_tree_add_boolean(field_tree, hf_appneta_resp_signature_flags_ext, tvb, offset + 5, 1, flags);
                            proto_tree_add_boolean(field_tree, hf_appneta_resp_signature_flags_iht, tvb, offset + 5, 1, flags);
                            proto_tree_add_boolean(field_tree, hf_appneta_resp_signature_flags_last, tvb, offset + 5, 1, flags);
                            proto_tree_add_boolean(field_tree, hf_appneta_resp_signature_flags_first, tvb, offset + 5, 1, flags);
                            break;
                        default:;
                    }
                    proto_tree_add_item(current_tree, hf_appneta_resp_signature_burst_len, tvb, offset + 6, 4, ENC_NA);
                    proto_tree_add_item(current_tree, hf_appneta_resp_signature_iht, tvb, offset + 10, 4, ENC_NA);
                } else {
                    /* this is a single-ended or ICMP extended packet signature found in payload */
                    proto_tree_add_item(current_tree, hf_appneta_resp_signature_iht, tvb, offset, 4, ENC_NA);
                }
                break;
            case HDR_PSEUDO_CKSUM:
                current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
                        "Pseudo Checksum");
                tf           = proto_tree_add_item(current_tree, hf_appneta_resp_pseudo_chksum, tvb, offset, 2, ENC_NA);
                field_tree   = proto_item_add_subtree(tf, ett_appneta_resp_pseudo_cksum);
                break;
            case HDR_IFACE_INFO:
                {
                    current_tree     = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
                                "Interface Info");
                    uint32_t flags32 = tvb_get_ntohl(tvb, offset);
                    uint32_t mtu     = tvb_get_ntohl(tvb, offset + 4);
                    uint32_t speed   = tvb_get_ntohl(tvb, offset + 8);

                    tf         = proto_tree_add_uint(current_tree, hf_appneta_resp_iface_info_flags, tvb, offset, 4, flags32);
                    field_tree = proto_item_add_subtree(tf, ett_appneta_resp_iface_info);
                    proto_tree_add_boolean(field_tree, hf_appneta_resp_iface_info_flags_is_appneta_resp_modified, tvb, offset, 4, flags32);
                    proto_tree_add_uint(current_tree, hf_appneta_resp_iface_info_mtu, tvb, offset + 4, 4, mtu);
                    proto_tree_add_uint(current_tree, hf_appneta_resp_iface_info_speed, tvb, offset + 8, 4, speed);
                    break;
                }
            case HDR_PUBLIC_IP_ADDRESS:
                current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
                        "Public IP Address");
                if (headerLength == 6) {
                    /* IPv4 */
                    proto_item *item;
                    uint32_t    addr = tvb_get_ipv4(tvb, offset);

                    tf         = proto_tree_add_ipv4(current_tree, hf_appneta_resp_public_ip, tvb, offset, 4, addr);
                    field_tree = proto_item_add_subtree(tf, ett_appneta_resp_public_ip_addr);
                    item       = proto_tree_add_ipv4(field_tree, hf_appneta_resp_public_ip_addr, tvb,
                                  offset, 4, addr);
                    PROTO_ITEM_SET_GENERATED(item);
                    PROTO_ITEM_SET_HIDDEN(item);
                } else if (headerLength == 18) {
                    /* IPv6 */
                    proto_item *item;
                    ws_in6_addr addr;
                    tvb_get_ipv6(tvb, offset, &addr);

                    tf         = proto_tree_add_ipv6(current_tree, hf_appneta_resp_public_ipv6, tvb, offset, IPv6_ADDR_SIZE, &addr);
                    field_tree = proto_item_add_subtree(tf, ett_appneta_resp_public_ip_addr);
                    item       = proto_tree_add_ipv6(field_tree, hf_appneta_resp_public_ipv6_addr, tvb,
                                  offset, IPv6_ADDR_SIZE, &addr);
                    PROTO_ITEM_SET_GENERATED(item);
                    PROTO_ITEM_SET_HIDDEN(item);
                }
                break;
            default:
                current_tree = add_subtree(tvb, &offset, current_tree, currentHeader, headerLength,
                        "Unknown Header");
                tf           = proto_tree_add_item(current_tree, hf_appneta_resp_unknown_header, tvb, offset, headerLength - 2, ENC_NA);
                field_tree   = proto_item_add_subtree(tf, ett_appneta_resp_invalid);

                /* set some text in the info column */
                col_append_fstr(pinfo->cinfo, COL_INFO, " [Unknown Header %u]", currentHeader);
        }

        offset += (headerLength - 2);
        currentHeader = nextHeader;
    }

    return offset;
}

/*******************************************************************
 * Code to dissect the packets targeting a Responder
 */
static int
dissect_appneta_responder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    unsigned int offset            = 0;
    proto_item  *ti                = NULL;
    proto_tree  *appneta_resp_tree = NULL;

    /* determine how many bytes of the packet will be processed */
    offset = dissect_rtp_header(tvb, pinfo, offset, NULL, TRUE);

    /* if not dissected, return 0 to indicate dissector disabled */
    if (!offset || tvb_captured_length(tvb) < offset)
        return 0;

    /* Make entry in Protocol column */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "AppNetaResponder");

    /* Indicate the number of bytes that will be processed */
    ti = proto_tree_add_item(tree, proto_appneta_resp, tvb, 0, offset, ENC_NA);

    /* Get a pointer to our subtree */
    appneta_resp_tree = proto_item_add_subtree(ti, ett_appneta_resp);

    /* Add items to our subtree */
    offset = 0;
    offset = dissect_rtp_header(tvb, pinfo, offset, appneta_resp_tree, FALSE);
    if (!offset)
        return 0;

    tvb    = tvb_new_subset_remaining(tvb, offset);
    offset = dissect_responder_header(tvb, pinfo, appneta_resp_tree, data);
    if (!offset)
        return 0;

    return call_dissector(appneta_payload_handle, tvb_new_subset_remaining(tvb, offset), pinfo, tree);
}

static int
dissect_appneta_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    uint32_t       path_payload_min_size = (sizeof(APPNETA_PAYLOAD_SIGNATURE) + 4);
    uint32_t       ecb_payload_min_size  = path_payload_min_size + 6;
    const uint32_t bytes                 = tvb_captured_length(tvb);
    proto_item    *ti;
    int            offset   = 0;
    const uint8_t *cp       = tvb_get_ptr(tvb, offset, bytes);
    tvbuff_t      *data_tvb = tvb;
    proto_tree    *data_tree;

    if (bytes >= sizeof(APPNETA_LEGACY_PAYLOAD_SIGNATURE) &&
            !memcmp(cp, APPNETA_LEGACY_PAYLOAD_SIGNATURE, sizeof(APPNETA_LEGACY_PAYLOAD_SIGNATURE))) {
        /* legacy packet */
        offset    = sizeof(APPNETA_LEGACY_PAYLOAD_SIGNATURE);
        ti        = proto_tree_add_protocol_format(tree, proto_appneta_payload, tvb,
                       0, offset, "AppNeta Legacy Payload");
        data_tree = proto_item_add_subtree(ti, ett_payload);
        proto_tree_add_item(data_tree, hf_payload_legacy_signature, data_tvb, 0, offset, ENC_NA);
        col_append_fstr(pinfo->cinfo, COL_INFO, " AppNeta Legacy Payload");
    } else if (bytes >= sizeof(APPNETA_LEGACY_PAYLOAD_SIGNATURE_CORRUPT) &&
               !memcmp(cp, APPNETA_LEGACY_PAYLOAD_SIGNATURE_CORRUPT, sizeof(APPNETA_LEGACY_PAYLOAD_SIGNATURE_CORRUPT))) {
        /* legacy packet */
        offset    = sizeof(APPNETA_LEGACY_PAYLOAD_SIGNATURE_CORRUPT);
        ti        = proto_tree_add_protocol_format(tree, proto_appneta_payload, tvb,
                       0, offset, "AppNeta Legacy Payload - CORRUPT");
        data_tree = proto_item_add_subtree(ti, ett_payload);
        proto_tree_add_item(data_tree, hf_payload_legacy_corrupt_signature, data_tvb, 0, offset, ENC_NA);
        col_append_fstr(pinfo->cinfo, COL_INFO, "  AppNeta Legacy Payload - CORRUPT");
    } else if (bytes >= (sizeof(PATHTEST_PAYLOAD_SIGNATURE) + 7) &&
               !memcmp(cp, PATHTEST_PAYLOAD_SIGNATURE, sizeof(PATHTEST_PAYLOAD_SIGNATURE))) {
        /* pathtest packet */
        offset                 = sizeof(PATHTEST_PAYLOAD_SIGNATURE);
        uint32_t burst_packets = tvb_get_ntohl(tvb, offset) >> 8;
        uint16_t seq           = tvb_get_ntohs(tvb, offset + 3);
        uint16_t stream        = tvb_get_ntohs(tvb, offset + 5);
        ti                     = proto_tree_add_protocol_format(tree, proto_appneta_payload, tvb,
                                    0, bytes, "PathTest Payload - stream=%u", stream);
        data_tree              = proto_item_add_subtree(ti, ett_payload);
        proto_tree_add_item(data_tree, hf_payload_pathtest_signature, data_tvb, 0, offset, ENC_NA);

        if (bytes == 18)
            proto_item_append_text(ti, " (Final)");
        else
            proto_item_append_text(ti, " seq=%u", seq);

        proto_tree_add_uint(data_tree, hf_payload_pathtest_burst_packets, tvb, offset, 3, burst_packets);
        proto_tree_add_uint(data_tree, hf_payload_pathtest_sequence, tvb, offset + 3, 2, seq);
        proto_tree_add_uint(data_tree, hf_payload_pathtest_stream, tvb, offset + 5, 2, stream);

        if (bytes == 18)
            col_append_fstr(pinfo->cinfo, COL_INFO, " PathTest payload - stream=%u (Final)", stream);
        else
            col_append_fstr(pinfo->cinfo, COL_INFO, " PathTest payload - stream=%u seq=%u", stream, seq);
        offset += 7;
    } else if (bytes >= path_payload_min_size &&
               (!memcmp(cp, APPNETA_PAYLOAD_SIGNATURE, sizeof(APPNETA_PAYLOAD_SIGNATURE)) || !memcmp(cp, APPNETA_REPLY_PAYLOAD_SIGNATURE, sizeof(APPNETA_REPLY_PAYLOAD_SIGNATURE)))) {
        /* path packet */
        uint32_t    iht_value = 0;
        const char *reply_str;
        char       *type_str;

        if (!memcmp(cp, APPNETA_REPLY_PAYLOAD_SIGNATURE, sizeof(APPNETA_REPLY_PAYLOAD_SIGNATURE))) {
            reply_str = "Reply ";
            type_str  = "appneta-reply-payload";
        } else {
            reply_str = "";
            type_str  = "appneta-payload";
        }

        offset                = sizeof(APPNETA_PAYLOAD_SIGNATURE);
        uint32_t status       = tvb_get_ntohl(tvb, offset);
        int      bit_offset   = offset * 8;
        uint8_t  flags        = (uint8_t)(status >> 28);
        bool     first        = !!(flags & 0x01);
        bool     last         = !!(flags & 0x02);
        uint32_t iht          = !!(flags & 0x04);
        bool     ext          = !!(flags & 0x08);
        uint32_t burst_length = ((status >> 8) & 0x000FFFFF);

        ti        = proto_tree_add_protocol_format(tree, proto_appneta_payload, tvb,
                       0, bytes, "AppNeta Path %sPayload", reply_str);
        data_tree = proto_item_add_subtree(ti, ett_payload);
        if (reply_str[0])
            proto_tree_add_item(data_tree, hf_payload_path_reply_signature, data_tvb, 0, offset, ENC_NA);
        else
            proto_tree_add_item(data_tree, hf_payload_path_signature, data_tvb, 0, offset, ENC_NA);

        proto_item *tf         = proto_tree_add_uint(data_tree, hf_payload_path_flags, tvb, offset, 1, flags);
        proto_tree *field_tree = proto_item_add_subtree(tf, ett_flags);

        if (first) {
            proto_item_append_text(ti, " (First)");
            proto_item_append_text(tf, " (First)");
        }

        if (last) {
            proto_item_append_text(ti, " (Last)");
            proto_item_append_text(tf, " (Last)");
        }

        if (iht) {
            iht_value = tvb_get_ntohl(tvb, offset + 3);
            proto_item_append_text(ti, " (iht)");
            proto_item_append_text(tf, " (iht)");
        }

        if (ext) {
            proto_item_append_text(ti, " (Ext)");
            proto_item_append_text(tf, " (Extended Headers)");
        }

        proto_tree_add_bits_item(field_tree, hf_payload_path_flags_ext, tvb, bit_offset + 0,
                1, ENC_BIG_ENDIAN);

        proto_tree_add_bits_item(field_tree, hf_payload_path_flags_iht, tvb, bit_offset + 1,
                1, ENC_BIG_ENDIAN);

        proto_tree_add_bits_item(field_tree, hf_payload_path_flags_last, tvb, bit_offset + 2,
                1, ENC_BIG_ENDIAN);

        proto_tree_add_bits_item(field_tree, hf_payload_path_flags_first, tvb, bit_offset + 3,
                1, ENC_BIG_ENDIAN);

        if (ext) {
            /* Extended headers*/
            ++offset;
            col_append_fstr(pinfo->cinfo, COL_INFO, " Extended %spayload", reply_str);
            if (!appneta_responder_handle)
                appneta_responder_handle = find_dissector("appneta_responder");

            if (appneta_responder_handle && bytes >= ecb_payload_min_size &&
                    tvb_captured_length_remaining(tvb, offset) > 0)
                call_dissector_with_data(appneta_responder_handle,
                        tvb_new_subset_remaining(tvb, offset),
                        pinfo, data_tree, type_str);

            return tvb_captured_length(tvb);
        }

        /* Path */
        proto_tree_add_uint(data_tree, hf_payload_path_burst_length, tvb, offset, 3, burst_length);
        proto_item_append_text(ti, " (%u bytes)", burst_length);

        if (iht) {
            proto_tree_add_uint(data_tree, hf_payload_path_iht_value, tvb, offset + 3, 4, iht_value);
            proto_item_append_text(ti, " (iht=%u nsec)", iht_value);
            offset += 4;
        }

        col_append_fstr(pinfo->cinfo, COL_INFO, " Path %spayload:", reply_str);
        col_append_fstr(pinfo->cinfo, COL_INFO, " first=%u last=%u", first, last);

        if (iht)
            col_append_fstr(pinfo->cinfo, COL_INFO, " iht=%u nsec", iht_value);

        col_append_fstr(pinfo->cinfo, COL_INFO, " burst=%u", burst_length);
        offset += sizeof(uint32_t) - 1;
    } else {
        return 0;
    }

    ti = proto_tree_add_protocol_format(tree, proto_appneta_payload, tvb,
            offset, tvb_reported_length_remaining(tvb, offset),
            "Data (%d byte%s)", bytes, plurality(bytes, "", "s"));

    data_tree = proto_item_add_subtree(ti, ett_data);
    return tvb_reported_length(tvb);
}

static bool
heur_dissect_appneta_responder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    return dissect_appneta_responder(tvb, pinfo, tree, data) > 0;
}

static bool
heur_dissect_appneta_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    if (dissect_appneta_payload(tvb, pinfo, tree, data) > 0) {
        col_append_sep_fstr(pinfo->cinfo, COL_PROTOCOL, NULL, "AppNetaPayload");
        return true;
    } else {
        return false;
    }
}

/* Register the protocols with Wireshark */
static void
register_appneta_responder(void)
{
    static hf_register_info hf[] = {
        { &hf_rtp_version,
         { "RTP Version", "appneta-resp.version", FT_UINT8, BASE_DEC, VALS(rtp_version_vals), 0xC0, "", HFILL }                                                  },
        { &hf_rtp_padding,
         { "RTP Padding", "appneta-resp.rtp.padding", FT_BOOLEAN, 8, NULL, 0x20, "", HFILL }                                                                     },
        { &hf_rtp_extension,
         { "RTP Extension", "appneta-resp.ext", FT_BOOLEAN, 8, NULL, 0x10, "", HFILL }                                                                           },
        { &hf_rtp_csrc_count,
         { "RTP Contributing source identifiers count", "appneta-resp.cc", FT_UINT8, BASE_DEC, NULL, 0x0F, "", HFILL }                                           },
        { &hf_rtp_marker,
         { "RTP Marker (Dual-ended)", "appneta-resp.marker", FT_BOOLEAN, 8, NULL, 0x80, "", HFILL }                                                              },
        { &hf_rtp_seq_nr,
         { "RTP Sequence number", "appneta-resp.seq", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }                                                                },
        { &hf_rtp_timestamp,
         { "RTP Timestamp", "appneta-resp.timestamp", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }                                                                },
        { &hf_rtp_ssrc,
         { "RTP SSRC (Flow ID)", "appneta-resp.ssrc", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }                                                                },
        { &hf_appneta_resp_next_header_type,
         { "Next Header Type", "appneta-resp.next_hdr_type", FT_UINT8, BASE_DEC, VALS(appneta_resp_header_type_vals), 0x0, "", HFILL }                           },
        { &hf_appneta_resp_header_length,
         { "Header Length", "appneta-resp.hdr_length", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }                                                                },
        { &hf_appneta_resp_pkt_id,
         { "Packet ID", "appneta-resp.pkt_id", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }                                                                       },
        { &hf_appneta_resp_error_code,
         { "Error Code", "appneta-resp.err_code", FT_UINT8, BASE_DEC, VALS(appneta_resp_error_code_vals), 0x0, "", HFILL }                                       },
        { &hf_appneta_resp_error_value,
         { "Error Value", "appneta-resp.err_value", FT_UINT8, BASE_HEX, NULL, 0x0, "", HFILL }                                                                   },
        { &hf_appneta_resp_response_status,
         { "Status", "appneta-resp.status", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }                                                                          },
        { &hf_appneta_resp_flow_num,
         { "Flow Number", "appneta-resp.flow_num", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }                                                                   },
        { &hf_appneta_resp_flow_port,
         { "Flow Port", "appneta-resp.flow_port", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }                                                                    },
        { &hf_appneta_resp_flow_port_first,
         { "Flow Port First", "appneta-resp.flow_port_first", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }                                                        },
        { &hf_appneta_resp_flow_port_last,
         { "Flow Port Last", "appneta-resp.flow_port_last", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }                                                          },
        { &hf_appneta_resp_test_weight,
         { "Test Weight", "appneta-resp.test_weight", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }                                                                },
        { &hf_appneta_resp_responder_version_major,
         { "Major", "appneta-resp.responder_version_major", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }                                                          },
        { &hf_appneta_resp_responder_version_minor,
         { "Minor", "appneta-resp.responder_version_minor", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }                                                          },
        { &hf_appneta_resp_responder_version_revision,
         { "Revision", "appneta-resp.responder_version_revision", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }                                                    },
        { &hf_appneta_resp_responder_version_build,
         { "Build", "appneta-resp.responder_version_build", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }                                                          },
        { &hf_appneta_resp_burst_size,
         { "Packets", "appneta-resp.burst_size", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }                                                                     },
        { &hf_appneta_resp_packet_size,
         { "Packet Size", "appneta-resp.packet_size", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }                                                                },
        { &hf_appneta_resp_command_type,
         { "Command Type", "appneta-resp.command_type", FT_UINT8, BASE_HEX, VALS(appneta_resp_cmd_type_vals), 0x0, "", HFILL }                                   },
        { &hf_appneta_resp_first_id,
         { "First Packet ID in Command", "appneta-resp.first_id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, "", HFILL }                                                },
        { &hf_appneta_resp_outbound_arrival_bits,
         { "Outbound Arrival Bits", "appneta-resp.outbound_bits", FT_UINT64, BASE_HEX, NULL, 0x0, "", HFILL }                                                    },
        { &hf_appneta_resp_burst_hold_time_us,
         { "Responder hold time usec", "appneta-resp.burst_hold_time", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }                                               },
        { &hf_appneta_resp_command_flags,
         { "Command Flags", "appneta-resp.command_flags", FT_UINT8, BASE_HEX, NULL, 0x0, "", HFILL }                                                             },
        { &hf_appneta_resp_command_flags_is_jumbo,
         { "Is Jumbo Packet", "appneta-resp.is_jumbo", FT_BOOLEAN, 8, NULL, 0x01, "", HFILL }                                                                    },
        { &hf_appneta_resp_command_flags_is_super_jumbo,
         { "Is Super Jumbo Packet", "appneta-resp.is_super_jumbo", FT_BOOLEAN, 8, NULL, 0x02, "", HFILL }                                                        },
        { &hf_appneta_resp_command_flags_is_inbound,
         { "Is Inbound Packet", "appneta-resp.is_inbound", FT_BOOLEAN, 8, NULL, 0x04, "", HFILL }                                                                },
        { &hf_appneta_resp_outbound_arrival_times,
         { "Outbound Arrival Times", "appneta-resp.outbound_times", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }                                                  },
        { &hf_appneta_resp_lost_id,
         { "Lost Packet ID", "appneta-resp.lost_id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, "", HFILL }                                                             },
        { &hf_appneta_resp_sipport,
         { "Sip Port", "appneta-resp.sip_port", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }                                                                      },
        { &hf_appneta_resp_ta_id,
         { "Traffic Analysys ID", "appneta-resp.ta_id", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }                                                             },
        { &hf_appneta_resp_protocol,
         { "Sequencer Protocol Version", "appneta-resp.protocol", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }                                                    },
        { &hf_appneta_resp_cb_inbound_packetcount,
         { "Inbound Packet Count", "appneta-resp.cb_inbound_packet_count", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }                                           },
        { &hf_appneta_resp_cb_inbound_interpacketgap,
         { "Inbound Inter-packet Gap (usec)", "appneta-resp.cb_inbound_interpacket_gap", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }                             },
        { &hf_appneta_resp_cb_outbound_packetcount,
         { "Outbound Packet Count", "appneta-resp.cb_outbound_packet_count", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }                                         },
        { &hf_appneta_resp_cb_outbound_interpacketgap,
         { "Outbound Inter-packet Gap (usec)", "appneta-resp.cb_outbound_interpacket_gap", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }                           },
        { &hf_appneta_resp_cb_inbound_flags_csv_debug,
         { "CSV Debug", "appneta-resp.cb_flags_is_csv_debug", FT_BOOLEAN, 32, NULL, 0x80000000, "", HFILL }                                                      },
        { &hf_appneta_resp_cb_resp_ratelimitcbrate,
         { "Rate Limit CB Rate", "appneta-resp.cb_resp_ratelimit_cb_rate", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }                                           },
        { &hf_appneta_resp_cb_resp_minpacketcount,
         { "Minimum Packet Count", "appneta-resp.cb_resp_min_packet_count", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }                                          },
        { &hf_appneta_resp_cb_request_reserved1,
         { "Rate Limit CB Request - reserved1", "appneta-resp.cb_resp_ratelimit_cb_request_reserved1", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }                },
        { &hf_appneta_resp_cb_request_reserved2,
         { "Rate Limit CB Request - reserved2", "appneta-resp.cb_resp_ratelimit_cb_request_reserved2", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }                },
        { &hf_appneta_resp_cb_ready_reserved1,
         { "Rate Limit CB Ready - reserved1", "appneta-resp.cb_resp_ratelimit_cb_ready_reserved1", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }                    },
        { &hf_appneta_resp_cb_ready_reserved2,
         { "Rate Limit CB Ready - reserved2", "appneta-resp.cb_resp_ratelimit_cb_ready_reserved2", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }                    },
        { &hf_appneta_resp_ecb_request_padding,
         { "ECB Request padding", "appneta-resp.ecb_request_padding", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }                                                 },
        { &hf_appneta_resp_ecb_request_flags,
         { "ECB Request flags", "appneta-resp.ecb_request_flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }                                                   },
        { &hf_appneta_resp_ecb_request_flags_first_seq,
         { "Is First sequence", "appneta-resp.ecb_request_flags.first", FT_BOOLEAN, 8, TFS(&appneta_tf_set_not_set), 0x01, "", HFILL }                           },
        { &hf_appneta_resp_ecb_request_flags_last_seq,
         { "Is Last sequence", "appneta-resp.ecb_request_flags.last", FT_BOOLEAN, 8, TFS(&appneta_tf_set_not_set), 0x02, "", HFILL }                             },
        { &hf_appneta_resp_ecb_request_flags_reply,
         { "Is Reply", "appneta-resp.ecb_request_flags.reply", FT_BOOLEAN, 8, TFS(&appneta_tf_set_not_set), 0x04, "", HFILL }                                    },
        { &hf_appneta_resp_ecb_request_flags_rx_report_all,
         { "RX Report All", "appneta-resp.ecb_request_flags.report_all", FT_BOOLEAN, 8, TFS(&appneta_tf_set_not_set), 0x08, "", HFILL }                          },
        { &hf_appneta_resp_ecb_request_flags_inbound_gap_ns,
         { "Inbound Gap Nanoseconds", "appneta-resp.ecb_request_flags.inbound_gap_nanoseconds", FT_BOOLEAN, 8, TFS(&appneta_tf_set_not_set), 0x10, "", HFILL }   },
        { &hf_appneta_resp_ecb_request_flags_outbound_gap_ns,
         { "Outbound Gap Nanoseconds", "appneta-resp.ecb_request_flags.outbound_gap_nanoseconds", FT_BOOLEAN, 8, TFS(&appneta_tf_set_not_set), 0x20, "", HFILL } },
        { &hf_appneta_resp_ecb_request_ssn,
         { "ECB Starting Sequence Number", "appneta-resp.ecb_request_ssn", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, "", HFILL }                                       },
        { &hf_appneta_resp_ecb_request_outbound_magnify,
         { "ECB Out-bound Magnification", "appneta-resp.ecb_request_outbound_magnify", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }                               },
        { &hf_appneta_resp_ecb_request_outbound_duration,
         { "ECB Out-bound Duration (msec)", "appneta-resp.ecb_request_outbound_duration", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }                            },
        { &hf_appneta_resp_ecb_request_outbound_gap,
         { "ECB Out-bound Inter-packet Gap (usec)", "appneta-resp.ecb_request_outbound_gap", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }                         },
        { &hf_appneta_resp_ecb_request_inbound_magnify,
         { "ECB In-bound Magnification", "appneta-resp.ecb_request_inbound_magnify", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }                                 },
        { &hf_appneta_resp_ecb_request_inbound_duration,
         { "ECB In-bound Duration (msec)", "appneta-resp.ecb_request_inbound_duration", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }                              },
        { &hf_appneta_resp_ecb_request_inbound_gap,
         { "ECB In-bound Inter-packet Gap (usec)", "appneta-resp.ecb_request_inbound_gap", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }                           },
        { &hf_appneta_resp_ecb_request_outbound_max_packets,
         { "ECB Out-bound Maximum Packets", "appneta-resp.ecb_request_outbound_max_packets", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }                         },
        { &hf_appneta_resp_ecb_request_inbound_max_packets,
         { "ECB In-bound Maximum Packets", "appneta-resp.ecb_request_inbound_max_packets", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }                           },
        { &hf_appneta_resp_ecb_resp_padding,
         { "ECB Response padding", "appneta-resp.ecb_resp_padding", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }                                                   },
        { &hf_appneta_resp_ecb_resp_flags,
         { "ECB Response flags", "appneta-resp.ecb_resp_flags", FT_UINT8, BASE_HEX, NULL, 0x0, "", HFILL }                                                       },
        { &hf_appneta_resp_ecb_resp_flags_in,
         { "In-bound results available", "appneta-resp.ecb_resp_flags.in", FT_BOOLEAN, 8, TFS(&appneta_tf_set_not_set), 0x01, "", HFILL }                        },
        { &hf_appneta_resp_ecb_resp_flags_out,
         { "Out-bound results available", "appneta-resp.ecb_resp_flags.out", FT_BOOLEAN, 8, TFS(&appneta_tf_set_not_set), 0x02, "", HFILL }                      },
        { &hf_appneta_resp_ecb_resp_flags_final,
         { "Final results", "appneta-resp.ecb_resp_flags.final", FT_BOOLEAN, 8, TFS(&appneta_tf_set_not_set), 0x04, "", HFILL }                                  },
        { &hf_appneta_resp_ecb_resp_outbound_first_tx_ts,
         { "ECB Response Out-bound TX timestamp (usecs)", "appneta-resp.ecb_resp_outbound_first_tx_ts", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }              },
        { &hf_appneta_resp_ecb_resp_outbound_first_rx_ts,
         { "ECB Response Out-bound First RX timestamp (usecs)", "appneta-resp.ecb_resp_outbound_first_rx_ts", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }        },
        { &hf_appneta_resp_ecb_resp_outbound_ll_rx,
         { "ECB Response Out-bound loss-less RX (packets)", "appneta-resp.ecb_resp_outbound_ll_rx", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }                  },
        { &hf_appneta_resp_ecb_resp_outbound_ll_rx_bytes,
         { "ECB Response Out-bound loss-less RX (bytes)", "appneta-resp.ecb_resp_outbound_ll_rx_bytes", FT_UINT64, BASE_DEC, NULL, 0x0, "", HFILL }              },
        { &hf_appneta_resp_ecb_resp_outbound_ll_us,
         { "ECB Response Out-bound loss-less RX timestamp (usec)", "appneta-resp.ecb_resp_outbound_ll_us", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }           },
        { &hf_appneta_resp_ecb_resp_outbound_total_rx,
         { "ECB Response Out-bound total RX (packets)", "appneta-resp.ecb_resp_outbound_total_rx", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }                   },
        { &hf_appneta_resp_ecb_resp_outbound_total_rx_bytes,
         { "ECB Response Out-bound total RX (bytes)", "appneta-resp.ecb_resp_outbound_total_rx_bytes", FT_UINT64, BASE_DEC, NULL, 0x0, "", HFILL }               },
        { &hf_appneta_resp_ecb_resp_outbound_total_us,
         { "ECB Response Out-bound total RX timestamp (usec)", "appneta-resp.ecb_resp_outbound_total_us", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }            },
        { &hf_appneta_resp_ecb_resp_inbound_first_tx_ts,
         { "ECB Response In-bound TX timestamp (usecs)", "appneta-resp.ecb_resp_inbound_first_tx_ts", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }                },
        { &hf_appneta_resp_ecb_resp_inbound_first_rx_ts,
         { "ECB Response In-bound First RX timestamp (usecs)", "appneta-resp.ecb_resp_inbound_first_rx_ts", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }          },
        { &hf_appneta_resp_ecb_resp_inbound_ll_rx,
         { "ECB Response In-bound loss-less RX (packets)", "appneta-resp.ecb_resp_inbound_ll_rx", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }                    },
        { &hf_appneta_resp_ecb_resp_inbound_ll_rx_bytes,
         { "ECB Response In-bound loss-less RX (bytes)", "appneta-resp.ecb_resp_inbound_ll_rx_bytes", FT_UINT64, BASE_DEC, NULL, 0x0, "", HFILL }                },
        { &hf_appneta_resp_ecb_resp_inbound_ll_us,
         { "ECB Response In-bound loss-less RX timestamp (usec)", "appneta-resp.ecb_resp_inbound_ll_us", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }             },
        { &hf_appneta_resp_ecb_resp_inbound_total_rx,
         { "ECB Response In-bound total RX (packets)", "appneta-resp.ecb_resp_inbound_total_rx", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }                     },
        { &hf_appneta_resp_ecb_resp_inbound_total_rx_bytes,
         { "ECB Response In-bound total RX (bytes)", "appneta-resp.ecb_resp_inbound_total_rx_bytes", FT_UINT64, BASE_DEC, NULL, 0x0, "", HFILL }                 },
        { &hf_appneta_resp_ecb_resp_inbound_total_us,
         { "ECB Response In-bound total RX timestamp (usec)", "appneta-resp.ecb_resp_inbound_total_us", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }              },
        { &hf_appneta_resp_pseudo_chksum,
         { "Pseudo Checksum", "appneta-resp.pseudo_cksum", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, "", HFILL }                                                       },
        { &hf_appneta_resp_iface_info_flags,
         { "Interface Flags", "appneta-resp.iface_flags", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }                                                            },
        { &hf_appneta_resp_iface_info_flags_is_appneta_resp_modified,
         { "Is AppNeta Modified", "appneta-resp.iface_is_appneta_resp_modified", FT_BOOLEAN, 32, NULL, 0x01, "", HFILL }                                         },
        { &hf_appneta_resp_iface_info_mtu,
         { "Interface MTU", "appneta-resp.iface_mtu", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }                                                                },
        { &hf_appneta_resp_iface_info_speed,
         { "Interface Speed", "appneta-resp.iface_speed", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }                                                            },
        { &hf_appneta_resp_inboundpacketcount,
         { "Inbound Packet Count", "appneta-resp.inbound_packet_count", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }                                              },
        { &hf_appneta_resp_inboundpacketsize,
         { "Inbound Packet Size", "appneta-resp.inbound_packet_size", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }                                                },
        { &hf_appneta_resp_h323port,
         { "H.323 Port", "appneta-resp.h323_port", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }                                                                   },
        { &hf_appneta_resp_appliance_type,
         { "Device Type", "appneta-resp.appliance_type", FT_UINT8, BASE_DEC, VALS(appneta_resp_appliance_type_vals), 0x0, "", HFILL }                            },
        { &hf_appneta_resp_custom_appliance_type,
         { "Custom Type", "appneta-resp.custom_appliance_type", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }                                                     },
        { &hf_appneta_resp_unknown_header,
         { "Unknown Header", "appneta-resp.unknown_header", FT_BYTES, BASE_NONE, NULL, 0x0, "", HFILL }                                                          },
        { &hf_appneta_resp_signature_undefined,
         { "Undefined Magic Number", "appneta-resp.signature.undefined_signature", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }                                 },
        { &hf_appneta_resp_signature_legacy,
         { "AppNeta Legacy Magic Number", "appneta-resp.signature.legacy_signature", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }                               },
        { &hf_appneta_resp_signature_path,
         { "AppNeta Path Magic Number", "appneta-resp.signature.path_signature", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }                                   },
        { &hf_appneta_resp_signature_path_reply,
         { "AppNeta Path Reply Magic Number", "appneta-resp.signature.path_reply_signature", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }                       },
        { &hf_appneta_resp_signature_pathtest,
         { "AppNeta PathTest Magic Number", "appneta-resp.signature.pathtest_signature", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }                           },
        { &hf_appneta_resp_signature_flags,
         { "Path flags", "appneta-resp.signature.path_flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }                                                       },
        { &hf_appneta_resp_signature_flags_first,
         { "First packet", "appneta-resp.signature.path_flags.first", FT_BOOLEAN, 8, TFS(&appneta_tf_set_not_set), 0x10, "", HFILL }                             },
        { &hf_appneta_resp_signature_flags_last,
         { "Last packet", "appneta-resp.signature.path_flags.last", FT_BOOLEAN, 8, TFS(&appneta_tf_set_not_set), 0x20, "", HFILL }                               },
        { &hf_appneta_resp_signature_flags_iht,
         { "Interrupt Hold Time (iht) available", "appneta-resp.signature.path_flags.iht", FT_BOOLEAN, 8, TFS(&appneta_tf_set_not_set), 0x40, NULL, HFILL }      },
        { &hf_appneta_resp_signature_flags_ext,
         { "Extended Headers", "appneta-resp.signature.path_flags.ext_hdr", FT_BOOLEAN, 8, TFS(&appneta_tf_set_not_set), 0x80, NULL, HFILL }                     },
        { &hf_appneta_resp_signature_iht,
         { "Interrupt Hold Time (iht)", "appneta-resp.signature.iht", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }                                                },
        { &hf_appneta_resp_signature_burst_len,
         { "Burst Length", "appneta-resp.signature.burst_len", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }                                                       },
        { &hf_appneta_resp_public_ip,
         { "Public Address", "appneta-resp.public_ip", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }                                                              },
        { &hf_appneta_resp_public_ip_addr,
         { "Public IPv4 Address", "appneta-resp.public_ip.addr", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }                                                    },
        { &hf_appneta_resp_public_ipv6,
         { "Public Address", "appneta-resp.public_ip", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }                                                              },
        { &hf_appneta_resp_public_ipv6_addr,
         { "Public IPv6 Address", "appneta-resp.public_ip.addr", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }                                                    },
    };

    /* Register the protocol name and description */
    proto_appneta_resp = proto_register_protocol("AppNeta Responder",
            "AppNetaResponder", "appneta_resp");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_appneta_resp, hf, array_length(hf));
    proto_register_subtree_array(ett_resp, array_length(ett_resp));

    register_dissector("appneta_responder", dissect_appneta_responder, proto_appneta_resp);
}

dissector_handle_t
get_value(void)
{
    return appneta_payload_handle;
}
void
register_appneta_payload(void)
{
    static hf_register_info hf[] = {
        { &hf_payload_legacy_signature,
         { "AppNeta Legacy Magic Number", "appneta_payload.legacy_signature", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }                                 },
        { &hf_payload_legacy_corrupt_signature,
         { "AppNeta Legacy Corrupt Magic Number", "appneta_payload.legacy_reply_signature", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }                   },
        { &hf_payload_path_signature,
         { "AppNeta Path Magic Number", "appneta_payload.path_signature", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }                                     },
        { &hf_payload_path_reply_signature,
         { "AppNeta Path Reply Magic Number", "appneta_payload.path_reply_signature", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }                         },
        { &hf_payload_data,
         { "Data", "appneta_payload.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }                                                                    },
        { &hf_payload_data_len,
         { "Length", "appneta_payload.len", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL }                                                                    },
        { &hf_payload_path_flags,
         { "Path flags", "appneta_payload.path_flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }                                                         },
        { &hf_payload_path_flags_first,
         { "First packet", "appneta_payload.path_flags.first", FT_BOOLEAN, BASE_NONE, TFS(&appneta_tf_set_not_set), 0x0, NULL, HFILL }                      },
        { &hf_payload_path_flags_last,
         { "Last packet", "appneta_payload.path_flags.last", FT_BOOLEAN, BASE_NONE, TFS(&appneta_tf_set_not_set), 0x0, NULL, HFILL }                        },
        { &hf_payload_path_flags_iht,
         { "Interrupt Hold Time (iht) available", "appneta_payload.path_flags.iht", FT_BOOLEAN, BASE_NONE, TFS(&appneta_tf_set_not_set), 0x0, NULL, HFILL } },
        { &hf_payload_path_flags_ext,
         { "Extended Headers", "appneta_payload.path_flags.ext", FT_BOOLEAN, BASE_NONE, TFS(&appneta_tf_set_not_set), 0x0, NULL, HFILL }                    },
        { &hf_payload_path_burst_length,
         { "Burst length", "appneta_payload.path_burst_length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }                                               },
        { &hf_payload_path_iht_value,
         { "iht value", "appneta_payload.path_iht_value", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }                                                     },
        { &hf_payload_pathtest_signature,
         { "PathTest Magic Number", "appneta_payload.pathtest_signature", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }                                     },
        { &hf_payload_pathtest_burst_packets,
         { "Burst packets", "appneta_payload.pathtest_burst_packets", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }                                         },
        { &hf_payload_pathtest_sequence,
         { "Sequence", "appneta_payload.pathtest_sequence", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }                                                   },
        { &hf_payload_pathtest_stream,
         { "Stream", "appneta_payload.pathtest_stream", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }                                                       },
    };

    static int *ett_pl[] = {
        &ett_payload,
        &ett_data,
        &ett_flags,
    };

    proto_appneta_payload = proto_register_protocol(
            "AppNeta Payload", /* name */
            "AppNetaPayload",  /* short name */
            "appneta_payload"  /* abbrev */
    );

    register_dissector("appneta_payload", dissect_appneta_payload, proto_appneta_payload);

    appneta_payload_handle = find_dissector("appneta_payload");

    /* Register preferences module */
    proto_reg_appneta_payload = prefs_register_protocol(proto_appneta_payload,
            proto_handoff_appneta_payload);

    proto_register_field_array(proto_appneta_payload, hf, array_length(hf));
    proto_register_subtree_array(ett_pl, array_length(ett_pl));

    ip_handle  = find_dissector("ip");
    ip6_handle = find_dissector("ip6");
}

void
proto_handoff_appneta_payload(void)
{
    appneta_responder_handle = find_dissector("appneta_responder");
    dissector_add_uint("udp.port", UDP_PORT_APPNETA_RESP, appneta_responder_handle);
}

void
proto_register_appneta(void)
{
    register_appneta_responder();
    register_appneta_payload();
}

void
proto_reg_handoff_appneta(void)
{
    /* Heuristic dissector for ICMP/ICMPv6 */
    heur_dissector_add("icmp", heur_dissect_appneta_payload, "AppNeta over ICMP", "appneta_icmp", proto_appneta_payload, HEURISTIC_ENABLE);
    heur_dissector_add("icmpv6", heur_dissect_appneta_payload, "AppNeta over ICMPv6", "appneta_icmpv6", proto_appneta_payload, HEURISTIC_ENABLE);
    heur_dissector_add("udp", heur_dissect_appneta_responder, "AppNeta over UDP", "appneta_udp", proto_appneta_resp, HEURISTIC_ENABLE);
    heur_dissector_add("tcp", heur_dissect_appneta_payload, "AppNeta over TCP", "appneta_tcp", proto_appneta_payload, HEURISTIC_ENABLE);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
