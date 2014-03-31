# Installer Makefile for Alpine Wall
# Copyright (C) 2012-2014 Kaarle Ritvanen
# See LICENSE file for license details

ROOT_DIR := /
LUA_VERSION := 5.1

resdir := usr/share/awall
confdir := etc/awall

all:	install

define mkdir =
$(ROOT_DIR)/$(1):
	install -d $$@

files += $(1)
endef

define copy =
$(ROOT_DIR)/$(2)/%.$(3): $(1)/%.$(3)
	install -d $$(dir $$@)
	install -m 644 $$< $$@

files += $(patsubst $(1)/%.$(3),$(2)/%.$(3),$(shell find $(1) -name '*.$(3)'))
endef

define rename =
$(ROOT_DIR)/$(2): $(1)
	install -d $$(dir $$@)
	install -m $(3) $(1) $$@

files += $(2)
endef

$(eval $(call copy,awall,usr/share/lua/$(LUA_VERSION)/awall,lua))
$(eval $(call copy,json,$(resdir)/mandatory,json))

$(eval $(call rename,awall-cli,usr/sbin/awall,755))
$(eval $(call rename,sample-policy.json,$(resdir)/sample/sample-policy.json,644))

$(eval $(call mkdir,$(confdir)))
$(eval $(call mkdir,$(confdir)/optional))
$(eval $(call mkdir,$(confdir)/private))
$(eval $(call mkdir,$(resdir)/optional))
$(eval $(call mkdir,$(resdir)/private))

$(ROOT_DIR)/$(resdir)/modules:
	install -d $(dir $@)
	ln -s ../lua/$(LUA_VERSION)/awall/modules $@

install: $(foreach f,$(files),$(ROOT_DIR)/$(f)) $(ROOT_DIR)/$(resdir)/modules

.PHONY: all
