#
# $Id: Custom.make $
#

_CUSTOM_SUBDIRS_ = \
	ani_rpp \
	ani_payload

_CUSTOM_EXTRA_DIST_ = \
	Custom.m4 \
	Custom.make

_CUSTOM_plugin_ldadd_ = \
	-dlopen plugins/ani_rpp/ani_rpp.la	\
	-dlopen plugins/ani_payload/ani_payload.la
