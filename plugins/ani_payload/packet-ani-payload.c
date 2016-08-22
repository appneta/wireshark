/* packet-ani-payload.c
 * Routines for packet payload disassembly
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */


#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/to_str.h>
#include "packet-ani-payload.h"

/* proto_data cannot be static because it's referenced in the
 * print routines
 */
void proto_register_ani_payload(void);

int proto_ani_payload = -1;

static int hf_payload_data = -1;
static int hf_payload_legacy_signature = -1;
static int hf_payload_path_signature = -1;
static int hf_payload_path_reply_signature = -1;
static int hf_payload_path_flags = -1;
static int hf_payload_path_flags_first = -1;
static int hf_payload_path_flags_last = -1;
static int hf_payload_path_flags_iht = -1;
static int hf_payload_path_burst_length = -1;
static int hf_payload_path_iht_value = -1;
static int hf_payload_pathtest_signature = -1;
static int hf_payload_pathtest_burst_packets = -1;
static int hf_payload_pathtest_sequence = -1;
static int hf_payload_pathtest_stream = -1;
static int hf_payload_flags = -1;
static int hf_payload_burst_size = -1;
static int hf_payload_data_len = -1;

static gboolean new_pane = FALSE;
static gboolean show_ani_payload = TRUE;

static gint ett_payload = -1;
static gint ett_flags = -1;

const unsigned char ANI_PAYLOAD_SIGNATURE[] = { 0xEC, 0xBD, 0x7F, 0x60, 0xFF };
const unsigned char ANI_REPLY_PAYLOAD_SIGNATURE[] = { 0xEC, 0xBD, 0x7F, 0x60, 0xFD };
const unsigned char ANI_LEGACY_PAYLOAD_SIGNATURE[] = { 0xEC, 0xBD, 0x7F, 0x60, 0x54, 0xD5 };
const unsigned char PATHTEST_PAYLOAD_SIGNATURE[] = { 0xEC, 0xBD, 0x7F, 0x60, 0xFE };

static const true_false_string ani_tf_set_not_set = {
	"Set",
	"Not Set"
};

static void
dissect_payload(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	guint bytes;

	if (show_ani_payload && tree) {
		bytes = tvb_captured_length_remaining(tvb, 0);
		if (bytes > 0) {
			tvbuff_t   *data_tvb;
			proto_item *ti, *tf;
			proto_tree *data_tree, *field_tree;
			gint offset = 0;
			const guint8 *cp = tvb_get_ptr(tvb, 0, bytes);

			if (new_pane) {
				guint8 *real_data = (guint8 *)tvb_memdup(wmem_packet_scope(), tvb, 0, bytes);
				data_tvb = tvb_new_child_real_data(tvb,real_data,bytes,bytes);
				tvb_set_free_cb(data_tvb, g_free);
				add_new_data_source(pinfo, data_tvb, "Not dissected data bytes");
			} else {
				data_tvb = tvb;
			}
			if (bytes >= sizeof(ANI_LEGACY_PAYLOAD_SIGNATURE) &&
					!memcmp(cp, ANI_LEGACY_PAYLOAD_SIGNATURE, sizeof(ANI_LEGACY_PAYLOAD_SIGNATURE))) {
				/* legacy packet */
				offset = sizeof(ANI_LEGACY_PAYLOAD_SIGNATURE);
				ti = proto_tree_add_protocol_format(tree, proto_ani_payload, tvb,
						0,
						bytes, "Data (%d byte%s) - ANI Legacy Payload", bytes,
						plurality(bytes, "", "s"));
				data_tree = proto_item_add_subtree(ti, ett_payload);

				proto_tree_add_item(data_tree, hf_payload_legacy_signature, data_tvb, 0, offset, ENC_NA);
				col_append_fstr(pinfo->cinfo, COL_INFO, ", ANI Legacy payload");
			} else if (bytes >= (sizeof(PATHTEST_PAYLOAD_SIGNATURE) + 7) &&
					!memcmp(cp, PATHTEST_PAYLOAD_SIGNATURE, sizeof(PATHTEST_PAYLOAD_SIGNATURE))) {
				/* pathtest packet */
				guint32 burst_packets;
				guint16 seq;
				guint16 stream;

				offset = sizeof(PATHTEST_PAYLOAD_SIGNATURE);
				burst_packets = tvb_get_ntohl(tvb, offset) >> 8;
				seq = tvb_get_ntohs(tvb, offset + 3);
				stream = tvb_get_ntohs(tvb, offset + 5);

				ti = proto_tree_add_protocol_format(tree, proto_ani_payload, tvb,
						0,
						bytes, "Data (%d byte%s) - PathTest Payload stream=%u", bytes,
						plurality(bytes, "", "s"), stream);
				data_tree = proto_item_add_subtree(ti, ett_payload);
				proto_tree_add_item(data_tree, hf_payload_pathtest_signature, data_tvb, 0, offset, ENC_NA);

				if (bytes == 18)
					proto_item_append_text(ti, " (Final)");
				else
					proto_item_append_text(ti, " seq=%u", seq);

				proto_tree_add_uint(data_tree, hf_payload_pathtest_burst_packets, tvb, offset, 3, burst_packets);
				proto_tree_add_uint(data_tree, hf_payload_pathtest_sequence, tvb, offset + 3, 2, seq);
				proto_tree_add_uint(data_tree, hf_payload_pathtest_stream, tvb, offset + 5, 2, stream);

				if (bytes == 18)
					col_append_fstr(pinfo->cinfo, COL_INFO, ", PathTest payload - stream=%u (Final)", stream);
				else
					col_append_fstr(pinfo->cinfo, COL_INFO, ", PathTest payload - stream=%u seq=%u", stream, seq);
				offset += 7;
			} else if (bytes >= (sizeof(ANI_PAYLOAD_SIGNATURE) + 4) &&
					(!memcmp(cp, ANI_PAYLOAD_SIGNATURE, sizeof(ANI_PAYLOAD_SIGNATURE))
							|| !memcmp(cp, ANI_REPLY_PAYLOAD_SIGNATURE, sizeof(ANI_REPLY_PAYLOAD_SIGNATURE)))) {
				/* path packet */
				guint32 status;
				gboolean first = FALSE;
				gboolean last = FALSE;
				gboolean iht = FALSE;
				guint8  flags;
				guint32 burst_length;
				guint32 iht_value;
				int bit_offset;
				const char *reply_str;

				if (!memcmp(cp, ANI_REPLY_PAYLOAD_SIGNATURE, sizeof(ANI_REPLY_PAYLOAD_SIGNATURE)))
					reply_str = "Reply ";
				else
					reply_str = "";

				offset = sizeof(ANI_PAYLOAD_SIGNATURE);
				status = tvb_get_ntohl(tvb, offset);
				bit_offset = offset * 8;
				flags = (guint8)(status >> 28);

				first = !!(flags & 0x01);
				last = !!(flags & 0x02);
				iht = !!(flags & 0x04);
				burst_length = ((status >> 8) & 0x000FFFFF);

				iht_value = tvb_get_ntohl(tvb, offset+3);

				ti = proto_tree_add_protocol_format(tree, proto_ani_payload, tvb,
						0,
						bytes, "Data (%d byte%s) - ANI Path %sPayload", bytes,
						plurality(bytes, "", "s"), reply_str);
				data_tree = proto_item_add_subtree(ti, ett_payload);
				if (reply_str[0])
					proto_tree_add_item(data_tree, hf_payload_path_reply_signature, data_tvb, 0, offset, ENC_NA);
				else
					proto_tree_add_item(data_tree, hf_payload_path_signature, data_tvb, 0, offset, ENC_NA);

				tf = proto_tree_add_uint(data_tree, hf_payload_path_flags, tvb, offset, 1, flags);
				field_tree = proto_item_add_subtree(tf, ett_flags);

				if (first) {
					proto_item_append_text(ti, " (First)");
					proto_item_append_text(tf, " (First)");
				}

				if (last) {
					proto_item_append_text(ti, " (Last)");
					proto_item_append_text(tf, " (Last)");
				}

				if (iht) {
					proto_item_append_text(ti, " (iht)");
					proto_item_append_text(tf, " (iht)");
				}

				proto_tree_add_bits_item(field_tree, hf_payload_path_flags_iht, tvb, bit_offset + 1,
						1, ENC_BIG_ENDIAN);

				proto_tree_add_bits_item(field_tree, hf_payload_path_flags_last, tvb, bit_offset + 2,
						1, ENC_BIG_ENDIAN);

				proto_tree_add_bits_item(field_tree, hf_payload_path_flags_first, tvb, bit_offset + 3,
						1, ENC_BIG_ENDIAN);

				proto_tree_add_uint(data_tree, hf_payload_path_burst_length, tvb, offset, 3, burst_length);
				proto_item_append_text(ti, " (%u bytes)", burst_length);

				if (iht) {
					proto_tree_add_uint(data_tree, hf_payload_path_iht_value, tvb, offset+3, 4, iht_value);
					proto_item_append_text(ti, " (%u nsec)", iht_value);
					offset += 4;
				}

				if (iht)
					col_append_fstr(pinfo->cinfo, COL_INFO, ", Path %spayload - first=%u last=%u burst=%u iht=%u",
							reply_str, first, last, burst_length, iht_value);
				else
					col_append_fstr(pinfo->cinfo, COL_INFO, ", Path %spayload - first=%u last=%u burst=%u",
							reply_str, first, last, burst_length);

				offset += sizeof(guint) - 1;
			} else {
				/* non-ANI packet */
				ti = proto_tree_add_protocol_format(tree, proto_ani_payload, tvb,
						0,
						bytes, "Data (%d byte%s)", bytes,
						plurality(bytes, "", "s"));
				data_tree = proto_item_add_subtree(ti, ett_payload);
			}

			proto_tree_add_item(data_tree, hf_payload_data, data_tvb, offset, bytes-offset, ENC_NA);
			ti = proto_tree_add_int(data_tree, hf_payload_data_len, data_tvb, 0, 0, bytes);
			PROTO_ITEM_SET_GENERATED (ti);
		}
	}
}

void
proto_register_ani_payload(void)
{
	static hf_register_info hf[] = {
		{ &hf_payload_burst_size,
			{ "Burst size", "ani_payload.burst_size", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_payload_flags,
			{ "Flags", "ani_payload.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
		{ &hf_payload_legacy_signature,
			{ "Legacy signature", "ani_payload.legacy_signature", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_payload_path_signature,
			{ "Path signature", "ani_payload.path_signature", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_payload_path_reply_signature,
			{ "Path Reply signature", "ani_payload.path_reply_signature", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_payload_data,
			{ "Data", "ani_payload.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_payload_data_len,
			{ "Length", "ani_payload.len", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_payload_path_flags,
			{ "Path flags", "ani_payload.path_flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
		{ &hf_payload_path_flags_first,
			{ "First packet", "ani_payload.path_flags.first", FT_BOOLEAN, BASE_NONE, TFS(&ani_tf_set_not_set), 0x0, NULL, HFILL } },
		{ &hf_payload_path_flags_last,
			{ "Last packet", "ani_payload.path_flags.last", FT_BOOLEAN, BASE_NONE, TFS(&ani_tf_set_not_set), 0x0, NULL, HFILL } },
		{ &hf_payload_path_flags_iht,
			{ "Interrupt Hold Time (iht) available", "ani_payload.path_flags.iht", FT_BOOLEAN, BASE_NONE, TFS(&ani_tf_set_not_set), 0x0, NULL, HFILL } },
		{ &hf_payload_path_burst_length,
			{ "Burst length", "ani_payload.path_burst_length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_payload_path_iht_value,
			{ "iht value", "ani_payload.path_iht_value", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_payload_pathtest_signature,
			{ "PathTest signature", "ani_payload.pathtest_signature", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_payload_pathtest_burst_packets,
			{ "Burst packets", "ani_payload.pathtest_burst_packets", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_payload_pathtest_sequence,
			{ "Sequence", "ani_payload.pathtest_sequence", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_payload_pathtest_stream,
			{ "Stream", "ani_payload.pathtest_stream", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
	};

	static gint *ett[] = {
			&ett_payload,
			&ett_flags,
	};

	module_t *module_data;

	proto_ani_payload = proto_register_protocol (
		"ANI Payload", /* name */
		"ANI_Payload", /* short name */
		"ani_payload" /* abbrev */
	);

	register_dissector("ani_payload", dissect_payload, proto_ani_payload);

	proto_register_field_array(proto_ani_payload, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	module_data = prefs_register_protocol(proto_ani_payload, NULL);
	prefs_register_bool_preference(module_data, "show_ani_payload",
			"Show dissected data on ANI payload",
			"Show dissected data on ANI payload in the Packet Details pane",
			&show_ani_payload);
}
