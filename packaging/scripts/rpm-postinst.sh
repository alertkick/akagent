#!/bin/sh
# This adds the proper /etc/rc*.d links for the script
[ -x /sbin/chkconfig ] && /sbin/chkconfig --add alertpriority-agent

mkdir -p /var/lib/alertpriority-agent
mkdir -p /usr/lib/alertpriority-agent/plugins
mkdir -p /etc/alertpriority-agent/

# Restart agent on upgrade
if [ "$1" = "2" ] ; then
    if [ -x "/bin/systemctl" ] ; then
      /bin/systemctl reload alertpriority-agent.service >/dev/null 2>&1 || true
      /bin/systemctl enable alertpriority-agent.service >/dev/null 2>&1 || true
      if [ -f "/etc/alertpriority-agent/alertpriority-agent-agent.conf" ] ; then
        /bin/systemctl restart alertpriority-agent.service >/dev/null 2>&1 || true
      fi
    else
      /sbin/service alertpriority-agent stop  >/dev/null 2>&1 || :
      /sbin/service alertpriority-agent start >/dev/null 2>&1 || :
    fi
fi
