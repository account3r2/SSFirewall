#!/bin/sh

# IPTables Firewall v1.2. Copyright (c) 2015 Niko Geil.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

echo "Firewall v1.2 by Niko Geil."

# Set up variables.
IPTABLES=/sbin/iptables
IPTABLESSAVE=/sbin/iptables-save
IPTABLESRESTORE=/sbin/iptables-restore
IPWHITELIST=/etc/network/firewall/ipwhitelist.txt
IPBLACKLIST=/etc/network/firewall/ipblacklist.txt
IPBLACKLISTBLOCKS=/etc/network/firewall/blocks
PORTWHITELISTUDP=/etc/network/firewall/portwhitelistudp.txt
PORTBLACKLISTUDP=/etc/network/firewall/portblacklistudp.txt
PORTWHITELISTTCP=/etc/network/firewall/portwhitelisttcp.txt
PORTBLACKLISTTCP=/etc/network/firewall/portblacklisttcp.txt
SSHPORT=22

# Get the IP address of home.
# If you're not Niko Geil, obviously remove this code.
SSHOME=$(dig +short home.serversquared.org | awk '{print; exit}')

# Flush any existing IPTables rules.
echo "Resetting IPTables rules."
$IPTABLES -F
$IPTABLES -X
$IPTABLES -Z

# Allow SSH on the port specified above.
# Don't touch this code you idiot.
# You don't want another incident.
echo "Accepting SSH connections on port $SSHPORT."
$IPTABLES -A INPUT -t filter -p tcp --dport $SSHPORT -j ACCEPT


# Check if black/whitelist files exist, if not, create them.
if [ ! -e $IPWHITELIST ]
then
echo "IP Whitelist not found, generating new file."
touch $IPWHITELIST
echo "# Any line in this file that does not start with a # is assumed to be an IP" >> $IPWHITELIST
echo "# address, and will be allowed by IPTables. Netmasks are accepted." >> $IPWHITELIST
echo "# Common Netmasks:" >> $IPWHITELIST
echo "# /8            x.0.0.0" >> $IPWHITELIST
echo "# /16           x.x.0.0" >> $IPWHITELIST
echo "# /24           x.x.x.0" >> $IPWHITELIST
fi
if [ ! -e $IPBLACKLIST ]
then
echo "IP Blacklist not found, generating new file."
touch $IPBLACKLIST
echo "# Any line in this file that does not start with a # is assumed to be an IP" >> $IPBLACKLIST
echo "# address, and will be blocked by IPTables. Netmasks are accepted." >> $IPBLACKLIST
echo "# Common Netmasks:" >> $IPBLACKLIST
echo "# /8            x.0.0.0" >> $IPBLACKLIST
echo "# /16           x.x.0.0" >> $IPBLACKLIST
echo "# /24           x.x.x.0" >> $IPBLACKLIST
fi
if [ ! -d $IPBLACKLISTBLOCKS ]
then
echo "IP Block Blacklist directory not found, creating directory."
mkdir $IPBLACKLISTBLOCKS
fi
if [ ! -e $PORTWHITELISTUDP ]
then
echo "UDP Port Whitelist not found, generating new file."
touch $PORTWHITELISTUDP
echo "# Any line in this file that does not start with a # is assumed to be a port" >> $PORTWHITELISTUDP
echo "# number, and will be allowed by IPTables." >> $PORTWHITELISTUDP
fi
if [ ! -e $PORTBLACKLISTUDP ]
then
echo "UDP Port Blacklist not found, generating new file."
touch $PORTBLACKLISTUDP
echo "# Any line in this file that does not start with a # is assumed to be a port" >> $PORTBLACKLISTUDP
echo "# number, and will be blocked by IPTables." >> $PORTBLACKLISTUDP
fi
if [ ! -e $PORTWHITELISTTCP ]
then
echo "TCP Port Whitelist not found, generating new file."
touch $PORTWHITELISTTCP
echo "# Any line in this file that does not start with a # is assumed to be a port" >> $PORTWHITELISTTCP
echo "# number, and will be allowed by IPTables." >> $PORTWHITELISTTCP
fi
if [ ! -e $PORTBLACKLISTTCP ]
then
echo "TCP Port Blacklist not found, generating new file."
touch $PORTBLACKLISTTCP
echo "# Any line in this file that does not start with a # is assumed to be a port" >> $PORTBLACKLISTTCP
echo "# number, and will be blocked by IPTables." >> $PORTBLACKLISTTCP
fi


# Blacklist.
# IPs.
for x in `grep -v ^# $IPBLACKLIST | awk '{print $1}'`; do
    echo "Dropping all packets from IP $x."
    $IPTABLES -A INPUT -t filter -s $x -j DROP
done
# TCP ports.
for x in `grep -v ^# $PORTBLACKLISTTCP | awk '{print $1}'`; do
    echo "Dropping all packets from TCP port $x."
    $IPTABLES -A INPUT -t filter -p tcp --dport $x -j DROP
done
# UDP ports.
for x in `grep -v ^# $PORTBLACKLISTUDP | awk '{print $1}'`; do
    echo "Dropping all packets from UDP port $x."
    $IPTABLES -A INPUT -t filter -p udp --dport $x -j DROP
done

# Whitelist.
# IPs.
for x in `grep -v ^# $IPWHITELIST | awk '{print $1}'`; do
    echo "Accepting packets from IP $x."
    $IPTABLES -A INPUT -t filter -s $x -j ACCEPT
done
# TCP ports.
for x in `grep -v ^# $PORTWHITELISTTCP | awk '{print $1}'`; do
    echo "Accepting packets on TCP port $x."
    $IPTABLES -A INPUT -t filter -p tcp --dport $x -j ACCEPT
done
# UDP ports.
for x in `grep -v ^# $PORTWHITELISTUDP | awk '{print $1}'`; do
    echo "Accepting packets on UDP port $x."
    $IPTABLES -A INPUT -t filter -p udp --dport $x -j ACCEPT
done

# Set default policies.
# Drop all incoming and forwarded packets, accept all outgoing packets.
echo "Dropping all incoming packets."
$IPTABLES -P INPUT DROP
echo "Dropping all forwarded packets."
$IPTABLES -P FORWARD DROP
echo "Accepting all outgoing packets."
$IPTABLES -P OUTPUT ACCEPT

# Allow all local packets.
echo "Accepting all local packets."
$IPTABLES -A INPUT -i lo -j ACCEPT

# Allow all packets from home.
# This might not be the safest thing ever.
# If you're not Niko Geil, obviously remove this code.
echo "Accepting all packets from $SSHOME."
$IPTABLES -A INPUT -t filter -s $SSHOME -j ACCEPT

# Allow all packets from established AND related connections.
echo "Accepting all packets from established and related connections."
$IPTABLES -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Save and load IPTables rules to/from file.
echo "Saving and applying settings."
$IPTABLESSAVE > /etc/iptables.rules
$IPTABLESRESTORE < /etc/iptables.rules
echo "Main firewall configuration complete."

# We're doing this after already saving because this can take a while.
# This may change in the future.
# The main issue with this method is that until the IP block rules have
# been applied, any IP address in the block can connect unless it has been
# blocked in one of the previous blacklists.
# Blacklist IP blocks.
echo "Dropping all packets from IP blocks in block directory."
echo "This may take a while."
for x in `grep -vh ^# $IPBLACKLISTBLOCKS/*.zone | awk '{print $1}'`; do
    $IPTABLES -A INPUT -t filter -s $x -j DROP
done
echo "Saving and applying settings."
$IPTABLESSAVE > /etc/iptables.rules
$IPTABLESRESTORE < /etc/iptables.rules
echo "Firewall configuration complete, IPTables rules are now active."

# Print rules.
#iptables -nvL --line-numbers
