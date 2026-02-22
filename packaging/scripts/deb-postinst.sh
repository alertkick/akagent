#!/bin/sh

if [ -f /etc/init.d/alertpriority-agent ] ; then
  update-rc.d alertpriority-agent defaults 91 09
fi

mkdir -p /var/lib/alertpriority-agent
mkdir -p /etc/alertpriority-agent/


legacy_start() {
  /etc/init.d/alertpriority-agent stop || :

  # Cleanup init's mess if it fails to stop
  PIDFILE=/var/run/alertpriority-agent.pid
  start-stop-daemon --stop --retry 5 --quiet --pidfile $PIDFILE --name alertpriority-agent-agent --signal KILL

  # Start only if we find a config file in place
  if [ -f /etc/alertpriority-agent/alertpriority-agent-agent.conf ]; then
    /etc/init.d/alertpriority-agent start || :
  fi

  exit $?
}

systemd_start() {
  systemctl reload alertpriority-agent.service >/dev/null 2>&1 || true
  systemctl enable alertpriority-agent.service >/dev/null 2>&1 || true
  if [ -f "/etc/alertpriority-agent/alertpriority-agent-agent.conf" ] ; then
    systemctl restart alertpriority-agent.service >/dev/null 2>&1 || true
  fi
}

case "$1" in
    configure)
      if which systemctl > /dev/null; then
        systemd_start
      elif [ -x "/etc/init.d/alertpriority-agent" ] || [ -e "/etc/init/alertpriority-agent.conf" ]; then
        legacy_start
      fi
      ;;
    remove)
      service alertpriority-agent stop || :
      rm -f /var/run/alertpriority-agent.pid
      ;;
    upgrade)
      ;;
    *)
      echo "Unrecognized postinst argument '$1'"
      ;;
esac
