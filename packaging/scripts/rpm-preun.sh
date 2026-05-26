#!/bin/sh
# Uninstall the service links on uninstall
if [ "$1" = "0" ] ; then
    /sbin/service alertkick-agent stop >/dev/null 2>&1 || :
    /sbin/chkconfig --del alertkick-agent
fi
