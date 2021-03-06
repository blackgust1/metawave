#############################################################
#
# autologin
#
#############################################################

# source included in buildroot
AUTOLOGIN_VERSION:=1.0
AUTOLOGIN_SOURCE =
HOST_AUTOLOGIN_SOURCE =

EXEC_AUTO = autologin

TARGET_LDFLAGS += -lpthread -lm
HOST_LDFLAGS += -lpthread -lm
TARGET_CFLAGS += -v
AUTOLOGIN_BUILD_DIR = package/autologin/



define AUTOLOGIN_BUILD_CMDS
	echo SHKO $(EXEC)
	cp -a package/autologin/* $(@D)
	$(MAKE1) -C $(@D)
endef

define AUTOLOGIN_INSTALL_TARGET_CMDS
	install -D -m 755 $(@D)/$(EXEC_AUTO) $(TARGET_DIR)/usr/sbin/$(EXEC_AUTO)
endef

define AUTOLOGIN_UNINSTALL_TARGET_CMDS
	rm -f $(TARGET_DIR)/usr/sbin/$(EXEC_AUTO)
endef


define HOST_AUTOLOGIN_BUILD_CMDS
	$(HOSTCC) $(HOST_CFLAGS) $(HOST_LDFLAGS) \
		package/autologin/autologin.c -o $(@D)/$(EXEC_AUTO)
endef

define HOST_AUTOLOGIN_INSTALL_CMDS
	install -D -m 755 $(@D)/$(EXEC_AUTO) $(HOST_DIR)/usr/bin/$(EXEC_AUTO)
endef

$(eval $(call GENTARGETS))
$(eval $(call GENTARGETS,host))
