#!/bin/sh

if [ -f /etc/init.d/alertkick-agent ] ; then
  update-rc.d alertkick-agent defaults 91 09
fi

mkdir -p /var/lib/alertkick-agent
mkdir -p /var/log/alertkick-agent
mkdir -p /etc/alertkick-agent/


legacy_start() {
  /etc/init.d/alertkick-agent stop || :

  # Cleanup init's mess if it fails to stop
  PIDFILE=/var/run/alertkick-agent.pid
  start-stop-daemon --stop --retry 5 --quiet --pidfile $PIDFILE --name alertkick-agent-agent --signal KILL

  # Start only if we find a config file in place
  if [ -f /etc/alertkick-agent/alertkick-agent-agent.conf ]; then
    /etc/init.d/alertkick-agent start || :
  fi

  exit $?
}

systemd_start() {
  systemctl reload alertkick-agent.service >/dev/null 2>&1 || true
  systemctl enable alertkick-agent.service >/dev/null 2>&1 || true
  if [ -f "/etc/alertkick-agent/alertkick-agent-agent.conf" ] ; then
    systemctl restart alertkick-agent.service >/dev/null 2>&1 || true
  fi
}

case "$1" in
    configure)
      if which systemctl > /dev/null; then
        systemd_start
      elif [ -x "/etc/init.d/alertkick-agent" ] || [ -e "/etc/init/alertkick-agent.conf" ]; then
        legacy_start
      fi
      ;;
    remove)
      service alertkick-agent stop || :
      rm -f /var/run/alertkick-agent.pid
      ;;
    upgrade)
      ;;
    *)
      echo "Unrecognized postinst argument '$1'"
      ;;
esac
