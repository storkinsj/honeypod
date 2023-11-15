#!/bin/sh

# Perform any pre-execution tasks if needed

# ensure DNS server is set.

if [[ -z "$dnsServer" ]]
then
    export dnsServer=1.1.1.1
fi
if [[ -z "$syslogServer" ]]
then
    export syslogServer=192.168.0.200
fi
if [[ -z "$HONEYPOD_LOG" ]]
then
    export HONEYPOD_LOG="/var/log/honeypod"
fi

## Configure Unbound ##

# Add Python module
echo  "server:" >> /usr/local/etc/unbound/unbound.conf
echo  "  chroot: \"\"" >> /usr/local/etc/unbound/unbound.conf
echo  "  module-config: \"python validator iterator\"" >> /usr/local/etc/unbound/unbound.conf
# Add interface config to unbound (in server clause)
echo "  interface: 0.0.0.0" >> /usr/local/etc/unbound/unbound.conf
echo "  interface: 127.0.0.1" >> /usr/local/etc/unbound/unbound.conf
# Add User name for runtime

echo  "  username: unbound" >> /usr/local/etc/unbound/unbound.conf

# Add upstream dns server from command line
echo "forward-zone:"  >> /usr/local/etc/unbound/unbound.conf
echo "  name: \".\"" >> /usr/local/etc/unbound/unbound.conf
echo "  forward-addr: $dnsServer" >> /usr/local/etc/unbound/unbound.conf

# Enable control
#echo "remote-control:"  >> /usr/local/etc/unbound/unbound.conf
#echo "  control-enable: yes" >> /usr/local/etc/unbound/unbound.conf


# Configure Python Domainfilter https://github.com/ohitz/unbound-domainfilter/tree/master
echo  "python:" >> /usr/local/etc/unbound/unbound.conf
echo  "  python-script: \"/app/honeypod/dnsfilter.py\"" >> /usr/local/etc/unbound/unbound.conf

# Restart unbound
#rc-service unbound restart

#
# TEMP
#
source /app/honeypod/cheatsheet

# set localhost (unbound) as our nameserver
echo  "nameserver 127.0.0.1" > /etc/resolv.conf
touch /var/log/honeypod
chown unbound /var/log/honeypod

# Start unbound
/usr/local/sbin/unbound -d&

# Start tcpdump monitor
#cd /app/p0f-master && /app/honeypod/P0fMonitor.py&
cd /app/ && /app/honeypod/TcpdumpMonitor.py

# Start syslog-ng as client
syslog-ng -f /etc/syslog-ng.conf&

# Execute any arguments to this script but standalone.
$@
