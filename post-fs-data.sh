#!/system/bin/sh
# The firewall is started from service.sh once the system is up. Keep this
# placeholder so KernelSU always finds a post-fs-data.sh entry point; nothing
# network-related should run this early.
exit 0
