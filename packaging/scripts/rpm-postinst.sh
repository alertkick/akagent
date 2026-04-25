#!/bin/sh
# This adds the proper /etc/rc*.d links for the script
[ -x /sbin/chkconfig ] && /sbin/chkconfig --add alertkick-agent

mkdir -p /var/lib/alertkick-agent
mkdir -p /var/log/alertkick-agent
mkdir -p /usr/lib/alertkick-agent/plugins
mkdir -p /etc/alertkick-agent/

# Restart agent on upgrade
if [ "$1" = "2" ] ; then
    if [ -x "/bin/systemctl" ] ; then
      /bin/systemctl reload alertkick-agent.service >/dev/null 2>&1 || true
      /bin/systemctl enable alertkick-agent.service >/dev/null 2>&1 || true
      if [ -f "/etc/alertkick-agent/alertkick-agent-agent.conf" ] ; then
        /bin/systemctl restart alertkick-agent.service >/dev/null 2>&1 || true
      fi
    else
      /sbin/service alertkick-agent stop  >/dev/null 2>&1 || :
      /sbin/service alertkick-agent start >/dev/null 2>&1 || :
    fi
fi
