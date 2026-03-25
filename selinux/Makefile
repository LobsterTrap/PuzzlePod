# SELinux policy module build for PuzzlePod
#
# Requirements:
#   dnf install selinux-policy-devel
#
# Usage:
#   make          — Build the policy module
#   make install  — Install and load the module
#   make clean    — Remove build artifacts

POLICY_NAME = puzzlepod
POLICY_VER  = 1.0.0

# Use the standard SELinux development makefile
SELINUX_DEVEL = /usr/share/selinux/devel
include $(SELINUX_DEVEL)/Makefile

.PHONY: install uninstall relabel clean-all

install: $(POLICY_NAME).pp
	semodule -i $(POLICY_NAME).pp
	restorecon -R /usr/bin/puzzled /usr/bin/puzzlectl 2>/dev/null || true
	restorecon -R /etc/puzzled 2>/dev/null || true
	restorecon -R /var/lib/puzzled 2>/dev/null || true
	restorecon -R /run/puzzled 2>/dev/null || true # R2: Restore runtime dir context
	restorecon -R /var/log/puzzled 2>/dev/null || true # R2: Restore log dir context

uninstall:
	semodule -r $(POLICY_NAME) 2>/dev/null || true

relabel:
	restorecon -R /usr/bin/puzzled /usr/bin/puzzlectl
	restorecon -R /etc/puzzled
	restorecon -R /var/lib/puzzled
	restorecon -R /run/puzzled 2>/dev/null || true # R2: Restore runtime dir context
	restorecon -R /var/log/puzzled 2>/dev/null || true # R2: Restore log dir context

clean-all: clean
	rm -f $(POLICY_NAME).pp
