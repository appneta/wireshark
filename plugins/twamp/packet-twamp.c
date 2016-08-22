/* packet-twamp.c
 * Routines for Two-Way Active Measurement Protocl (TWAMP) dissection
 *
 * Currently only implements dissection for unauthenticated packets (TWAMP Light)
 * Copyright (c) 2015 AppNeta
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"
#include <math.h>
#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>

void proto_reg_handoff_twamp(void);
void proto_register_twamp(void);

static dissector_handle_t data_handle;

static int proto_twamp = -1;

static int hf_twamp_seq = -1;
static int hf_twamp_timestamp = -1;
static int hf_twamp_timestamp_synced = -1;
static int hf_twamp_error_scale = -1;
static int hf_twamp_error_multi = -1;
static int hf_twamp_receive_timestamp = -1;
static int hf_twamp_sender_seq = -1;
static int hf_twamp_sender_timestamp = -1;
static int hf_twamp_sender_timestamp_synced = -1;
static int hf_twamp_sender_error_scale = -1;
static int hf_twamp_sender_error_multi = -1;
static int hf_twamp_sender_ttl = -1;

static gint ett_twamp = -1;
static gint ett_twamp_error_estim = -1;
static gint ett_twamp_receive_estim = -1;

/* Global port preference */
static guint gTWAMP_PORT = 6000;

/* dissect unauthenticated twamp packets (TWAMP Light) */
static int
dissect_twamp_unauth(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
    /* SUBTREE VARIABLES AND MISC LOCALS */
    proto_item *ti;
    proto_tree *twamp_tree, *error_estim_tree;

    guint error_bytes, seq_num_bytes;
    gboolean is_request_packet;
    guint offset = 0;

    /* CHECK FOR REQUEST PACKET */
    /* if the receive timestamp field is zeroed,
     * this packet has not been reflected yet */
    is_request_packet = (tvb_get_ntoh40(tvb, 24) == 0);

    /* SET INFO COLUMN */
    if (is_request_packet) {
        col_set_str(pinfo->cinfo, COL_INFO, "TWAMP Request: ");
    } else {
        col_set_str(pinfo->cinfo, COL_INFO, "TWAMP Reply: ");
    }

    /*** PROTOCOL TREE ***/
    /* create display subtree for the TWAMP light protocol */
    ti = proto_tree_add_item(tree, proto_twamp, tvb, 0, -1, ENC_NA);
    twamp_tree = proto_item_add_subtree(ti, ett_twamp);

    /* add packet fields to the subtree */
    proto_tree_add_item(twamp_tree, hf_twamp_seq,
        tvb, offset, 4, ENC_BIG_ENDIAN);
    if (is_request_packet) {
        seq_num_bytes = tvb_get_ntoh40(tvb, offset);
        if (seq_num_bytes) {
            col_append_fstr(pinfo->cinfo, COL_INFO, "Sequence Number = %i", seq_num_bytes);
        }
    }
    offset+=4;

    proto_tree_add_item(twamp_tree, hf_twamp_timestamp,
        tvb, offset, 8, ENC_TIME_NTP|ENC_BIG_ENDIAN);
    offset+=8;

    /* parse the error estimate field in a subtree */
    error_estim_tree = proto_tree_add_subtree(twamp_tree, tvb, offset, 2,
        ett_twamp_error_estim, NULL, "Error Estimate");

    error_bytes = (gboolean) tvb_get_guint8(tvb, offset);
    proto_tree_add_boolean(error_estim_tree, hf_twamp_timestamp_synced,
        tvb, offset, 1, (gboolean) error_bytes >> 7);
    proto_tree_add_uint(error_estim_tree, hf_twamp_error_scale,
        tvb, offset, 1, (guint8) error_bytes & 0x3f);
    proto_tree_add_item(error_estim_tree, hf_twamp_error_multi,
        tvb, offset+1, 1, ENC_BIG_ENDIAN);
    offset+=4; /*error bytes followed by two-byte MBZ*/

    /* add the receiver timestamp to the twamp tree */
    proto_tree_add_item(twamp_tree, hf_twamp_receive_timestamp,
        tvb, offset, 8, ENC_TIME_NTP|ENC_BIG_ENDIAN);
    offset+=8;

    proto_tree_add_item(twamp_tree, hf_twamp_sender_seq,
        tvb, offset, 4, ENC_BIG_ENDIAN);
    if (! is_request_packet) {
        seq_num_bytes = tvb_get_ntoh40(tvb, offset);
        if (seq_num_bytes) {
            col_append_fstr(pinfo->cinfo, COL_INFO, "Sequence Number = %i", seq_num_bytes);
        }
    }
    offset+=4;

    proto_tree_add_item(twamp_tree, hf_twamp_sender_timestamp,
        tvb, offset, 8, ENC_TIME_NTP|ENC_BIG_ENDIAN);
    offset+=8;

    /* parse the sender error estimate field in a subtree */
    error_estim_tree = proto_tree_add_subtree(twamp_tree, tvb, offset, 2,
        ett_twamp_receive_estim, NULL, "Sender Error Estimate");

    error_bytes = tvb_get_guint8(tvb, offset);
    proto_tree_add_boolean(error_estim_tree, hf_twamp_sender_timestamp_synced,
        tvb, offset, 1, (gboolean) error_bytes >> 7);
    proto_tree_add_uint(error_estim_tree, hf_twamp_sender_error_scale,
        tvb, offset, 1, (guint8) error_bytes & 0x3f);
    proto_tree_add_item(error_estim_tree, hf_twamp_sender_error_multi,
        tvb, offset+1, 1, ENC_BIG_ENDIAN);
    offset+=4; /*error bytes followed by two-byte MBZ*/

    /* sender ttl in main tree */
    proto_tree_add_item(twamp_tree, hf_twamp_sender_ttl,
        tvb, offset, 1, ENC_BIG_ENDIAN);
    offset+=1;

    /* pass remaining data to data handler */
    if (tvb_captured_length_remaining(tvb, offset) > 0)
        call_dissector(data_handle, tvb_new_subset_remaining(tvb, offset),
            pinfo, twamp_tree);

    return tvb_captured_length(tvb);
} /* end dissect_twamp_unauth */

static int
dissect_twamp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
    /*** COLUMN DATA ***/
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "TWAMP");
    col_clear(pinfo->cinfo, COL_INFO);
    col_set_str(pinfo->cinfo, COL_INFO, "TWAMP Test Packet");

    /*** HEURISTICS ***/
    /* Check MBZ fields for unauthenticated TWAMP packets */
    if (tvb_get_ntohs(tvb, 14) == 0 && tvb_get_ntohs(tvb, 38) == 0) {
        return dissect_twamp_unauth(tvb, pinfo, tree, data);
    } else {
        /* dissection not supported or invalid packet */
        return 0;
    }
}

void
proto_register_twamp(void)
{
    module_t *twamp_module;

    /* Setup list of header fields  See Section 1.5 of README.dissector for
     * details. */
    static hf_register_info hf[] = {
        { &hf_twamp_seq,
        { "Sequence Number", "twamp.seq",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_twamp_timestamp,
        { "Timestamp", "twamp.timestamp",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_twamp_timestamp_synced,
        { "Timestamp Synced", "twamp.timestamp_synced",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_twamp_error_scale,
        { "Error Scale", "twamp.error_scale",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_twamp_error_multi,
        { "Error Multiplier", "twamp.error_multi",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_twamp_receive_timestamp,
        { "Receive Timestamp", "twamp.receiver.timestamp",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_twamp_sender_seq,
        { "Sender Sequence Number", "twamp.sender.seq",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_twamp_sender_timestamp,
        { "Sender Timestamp", "twamp.sender.timestamp",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_twamp_sender_timestamp_synced,
        { "Sender Timestamp Synced", "twamp.sender.timestamp_synced",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_twamp_sender_error_scale,
        { "Sender Error Scale", "twamp.sender.error_scale",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_twamp_sender_error_multi,
        { "Sender Error Multiplier", "twamp.sender.error_multi",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_twamp_sender_ttl,
        { "Sender TTL", "twamp.sender.ttl",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_twamp,
        &ett_twamp_error_estim,
        &ett_twamp_receive_estim,
    };

    /* Register the protocol name and description */
    proto_twamp = proto_register_protocol("Two-Way Active Measurement Protocl",
            "TWAMP", "twamp");

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_twamp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register preferences */
    twamp_module = prefs_register_protocol(proto_twamp, proto_reg_handoff_twamp);

    /* Register a port preference */
    prefs_register_uint_preference(twamp_module, "udp.port", "TWAMP UDP Port",
            " TWAMP UDP port if other than the default",
            10, &gTWAMP_PORT);
} /* end proto_register_twamp */

void proto_reg_handoff_twamp(void)
{
    static gboolean initialized = FALSE;
    static dissector_handle_t twamp_handle;
    static int currentPort;

    if (!initialized) {
        twamp_handle = new_create_dissector_handle(dissect_twamp, proto_twamp);
        currentPort = gTWAMP_PORT;
        initialized = TRUE;

        /* get the handle for the data handler */
        data_handle = find_dissector("data");
    } else {
        /* needed to change the configured port */
        dissector_delete_uint("udp.port", currentPort, twamp_handle);
        currentPort = gTWAMP_PORT;
    }

    dissector_add_uint("udp.port", gTWAMP_PORT, twamp_handle);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
