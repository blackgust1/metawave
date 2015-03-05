#############################################################
#
# libqwt
#
#############################################################
LIBQWT_VERSION = 6.0.1
LIBQWT_SOURCE = qwt-$(LIBQWT_VERSION).tar.bz2
LIBQWT_SITE = http://$(BR2_SOURCEFORGE_MIRROR).dl.sourceforge.net/project/qwt/qwt/$(LIBQWT_VERSION)/
LIBQWT_INSTALL_STAGING = YES
LIBQWT_DEPENDENCIES = qt

LIBQWT_CONFIG  =    's%QWT_INSTALL_PREFIX.*/usr/local/.*%QWT_INSTALL_PREFIX = /usr%'
LIBQWT_CONFIG += -e 's/^.*QWT_CONFIG.*QwtDesigner.*$$/\# QWT_CONFIG += QwtDesigner/'
LIBQWT_CONFIG += -e 's%/features%/mkspecs/features%'

ifeq ($(BR2_PACKAGE_LIBQWT_SVG),y)
	LIBQWT_CONFIG += -e 's/^.*QWT_CONFIG.*QwtSvg.*$$/QWT_CONFIG += QwtSvg/'
else
	LIBQWT_CONFIG += -e 's/^.*QWT_CONFIG.*QwtSvg.*$$/\# QWT_CONFIG += QwtSvg/'
endif

ifeq ($(BR2_PACKAGE_LIBQWT_MATHML),y)
	LIBQWT_CONFIG += -e 's/^.*QWT_CONFIG.*QwtMathML.*$$/QWT_CONFIG += QwtMathML/'
else
	LIBQWT_CONFIG += -e 's/^.*QWT_CONFIG.*QwtMathML.*$$/\# QWT_CONFIG += QwtMathML/'
endif

define LIBQWT_CONFIGURE_CMDS
	$(SED) $(LIBQWT_CONFIG) $(@D)/qwtconfig.pri
	(cd $(@D); $(QT_QMAKE))
endef

define LIBQWT_BUILD_CMDS
	$(MAKE) -C $(@D)
endef

define LIBQWT_INSTALL_STAGING_CMDS
	$(MAKE) -C $(@D) install INSTALL_ROOT=$(STAGING_DIR)
endef

define LIBQWT_INSTALL_TARGET_CMDS
	$(MAKE) -C $(@D) install INSTALL_ROOT=$(TARGET_DIR)
	rm -Rf $(TARGET_DIR)/usr/mkspecs
endef

$(eval $(call GENTARGETS))
