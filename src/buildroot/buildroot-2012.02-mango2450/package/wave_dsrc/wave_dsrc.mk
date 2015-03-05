#############################################################
#
# autologin
#
#############################################################

# source included in buildroot
WAVE_DSRC_VERSION:=1.0
WAVE_DSRC_SOURCE =
HOST_WAVE_DSRC_SOURCE =

EXEC = wavedsrc

TARGET_LDFLAGS += -lpthread -lm
HOST_LDFLAGS += -lpthread -lm
TARGET_CFLAGS += -v
WAVE_BUILD_DIR = package/wave_dsrc/



define WAVE_DSRC_BUILD_CMDS
	echo SHKO $(EXEC)
	cp -a package/wave_dsrc/* $(@D)
	$(MAKE1) -C $(@D)
endef

define WAVE_DSRC_INSTALL_TARGET_CMDS
	install -D -m 755 $(@D)/$(EXEC) $(TARGET_DIR)/usr/sbin/$(EXEC)
endef

define WAVE_DSRC_UNINSTALL_TARGET_CMDS
	rm -f $(TARGET_DIR)/usr/sbin/$(EXEC)
endef


define HOST_WAVE_DSRC_BUILD_CMDS
	$(HOSTCC) $(HOST_CFLAGS) $(HOST_LDFLAGS) \
		package/wave_dsrc/main.c package/wave_dsrc/monitor.c package/wave_dsrc/network.c \
		package/wave_dsrc/util.c package/wave_dsrc/wave_int.c package/wave_dsrc/wave_mac.c \
		package/wave_dsrc/wave_modem.c -o $(@D)/$(EXEC)
endef


define HOST_WAVE_DSRC_INSTALL_CMDS
	install -D -m 755 $(@D)/$(EXEC) $(HOST_DIR)/usr/bin/$(EXEC)
endef


$(eval $(call GENTARGETS))
$(eval $(call GENTARGETS,host))
