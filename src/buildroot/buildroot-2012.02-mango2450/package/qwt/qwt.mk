######################################################################
#
# QWT
#
######################################################################

QWT_VERSION:=6.0.1
QWT_SOURCE:=qwt-$(QWT_VERSION).zip
QWT_SITE:=https://sourceforge.net/projects/qwt/files/qwt/$(QWT_VERSION)
QWT_UNZIP:=unzip
QWT_TARGET_DIR:=$(BUILD_DIR)/qwt-$(QWT_VERSION)
QWT_CONFIG_FILE:=qwt.pro
QMAKE_DIR:=$(HOST_DIR)/usr

$(DL_DIR)/$(QWT_SOURCE):
	$(call DOWNLOAD,$(QWT_SITE),$(QWT_SOURCE))

qwt-source: $(DL_DIR)/$(QWT_SOURCE)

$(QWT_TARGET_DIR)/.unpacked: $(DL_DIR)/$(QWT_SOURCE)
	$(QWT_UNZIP) -d $(BUILD_DIR) $(DL_DIR)/$(QWT_SOURCE)
	toolchain/patch-kernel.sh $(QWT_TARGET_DIR) package/qwt/ \
		qwt-$(QWT_VERSION)-\*.patch \
		qwt-$(QWT_VERSION)-\*.patch.$(ARCH)
	touch $@

$(QWT_TARGET_DIR)/.configured: $(QWT_TARGET_DIR)/.unpacked
	-[ -f $(QWT_TARGET_DIR)/Makefile ] && $(MAKE) -C $(QWT_TARGET_DIR) distclean
	$(QMAKE_DIR)/bin/qmake $(QWT_TARGET_DIR)/$(QWT_CONFIG_FILE)
	touch $@

$(QWT_TARGET_DIR)/.compiled: $(QWT_TARGET_DIR)/.configured
	$(MAKE) -C $(QWT_TARGET_DIR)
	touch $@

$(STAGING_DIR)/usr/lib/libqwt.so: $(QWT_TARGET_DIR)/.compiled
	(export INSTALL_ROOT=$(STAGING_DIR); $(MAKE) -C $(QWT_TARGET_DIR) install)

$(TARGET_DIR)/usr/lib/libqwt.so: $(STAGING_DIR)/usr/lib/libqwt.so
	cp -dpf $(STAGING_DIR)/usr/lib/libqwt.so* $(TARGET_DIR)/usr/lib/
	-$(STRIPCMD) $(STRIP_STRIP_UNNEEDED) $(TARGET_DIR)/usr/lib/libqwt.so*

qwt: qt $(TARGET_DIR)/usr/lib/libqwt.so

qwt-clean:
	-$(MAKE) -C $(QWT_TARGET_DIR) clean
	-rm $(TARGET_DIR)/usr/lib/libqwt.so.*
	-rm $(STAGING_DIR)/usr/lib/libqwt.so.*

qwt-dirclean:
	rm -rf $(QWT_TARGET_DIR)

#############################################################
#
# Toplevel Makefile options
#
#############################################################
ifeq ($(BR2_PACKAGE_QWT),y)
TARGETS+=qwt
endif
