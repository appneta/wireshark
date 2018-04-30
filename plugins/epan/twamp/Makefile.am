# Makefile.am
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

include $(top_srcdir)/Makefile.am.inc
include $(top_srcdir)/plugins/epan/Makefile.am.inc

# the name of the plugin
PLUGIN_NAME = twamp

PLUGIN_VERSION = 0.0.1

# Non-generated sources
NONGENERATED_C_FILES = \
	$(NONGENERATED_REGISTER_C_FILES) \
	packet-twamp.c

# Headers.
CLEAN_HEADER_FILES =

HEADER_FILES = \
	$(CLEAN_HEADER_FILES)

epan_plugin_LTLIBRARIES = twamp.la

twamp_la_SOURCES = \
	$(SRC_FILES)	\
	$(HEADER_FILES)

twamp_la_CPPFLAGS = $(AM_CPPFLAGS) $(PLUGIN_CPPFLAGS)

twamp_la_CFLAGS = $(AM_CFLAGS) $(PLUGIN_CFLAGS)

twamp_la_LDFLAGS = $(PLUGIN_LDFLAGS)

EXTRA_DIST = \
	CMakeLists.txt
