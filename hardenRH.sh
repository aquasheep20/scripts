#!/bin/bash
# Copyright (c) 2017 Mike Zeece <mzeece@pmcrock.com>
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. Neither the name of mosquitto nor the names of its
#    contributors may be used to endorse or promote products derived from
#    this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

if [ -f /etc/modprobe.d/CIS.conf ]; then
    echo "Harden can only be run once, exiting"
    exit
fi
echo "Processing"
cp /etc/fstab /etc/fstab.hardenbk
cp /etc/postfix/main.cf /etc/postfix/main.cf.hardenbk
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.hardenbk
cp /etc/pam.d/common-password /etc/pam.d/common-password.hardenbk
cp /etc/security/pwquality.conf /etc/security/pwquality.conf.hardenbk
cp /etc/login.defs /etc/login.defs.hardenbk
#This script will harden a default 16.04LTS to CIS level1 with Arrow conessions
#1.1.1.1 Ensure mounting of cramfs filesystems is disabled
echo "install cramfs /bin/true" >> /etc/modprobe.d/CIS.conf
#1.1.1.2 Ensure mounting of freevxfs filesystems is disabled
echo "install freevxfs /bin/true" >> /etc/modprobe.d/CIS.conf
#1.1.1.3 Ensure mounting of jffs2 filesystems is disabled
echo "install jffs2 /bin/true" >> /etc/modprobe.d/CIS.conf
#1.1.1.4 Ensure mounting of hfs filesystems is disabled
echo "install hfs /bin/true" >> /etc/modprobe.d/CIS.conf
#1.1.1.5 Ensure mounting of hfsplus filesystems is disabled
echo "install hfsplus /bin/true" >> /etc/modprobe.d/CIS.conf
#1.1.1.6 Ensure mounting of squashfs filesystems is disabled - cannot be removed, compiled into kernel: modprobe -r -v squashfs: modprobe: FATAL: Module squashfs is builtin.
#echo "install squashfs /bin/true" >> /etc/modprobe.d/CIS.conf
#1.1.1.7 Ensure mounting of udf filesystems is disabled
echo "install udf /bin/true" >> /etc/modprobe.d/CIS.conf
#1.1.1.8 Ensure mounting of FAT filesystems is disabled - cannot be removed, compiled into kernel
##echo "install vfat /bin/true" >> /etc/modprobe.d/CIS.conf
#1.1.16 Ensure noexec option set on /dev/shm partition
echo "tmpfs                   /dev/shm                tmpfs   defaults,nodev,nosuid,noexec        0 0" >> /etc/fstab
#1.3.2 Ensure filesystem integrity is regularly checked
crontab -l > rootcron
echo "0 5 * * * /usr/bin/aide --check" >> rootcron
awk '!x[$0]++' rootcron | tee rootcron
crontab rootcron
rm rootcron
#1.4.1 Ensure permissions on bootloader config are configured
chown root:root /boot/grub2/grub.cfg
chmod og-rwx /boot/grub2/grub.cfg
#1.5.1 Ensure core dumps are restricted
echo "*   hard    core   0" >> /etc/security/limits.d/98-CIS.conf
sysctl -q -n -w kernel.randomize_va_space=2
echo "kernel.randomize_va_space = 2 " >> /etc/sysctl.conf
#2.2.1.5
yum remove xinetd
yum remove telnet-server
yum remove rsh-server
yum remove telnet
yum remove rsh-server
yum remove rsh
yum remove ypbind
yum remove ypserv
yum remove tftp-server
yum remove cronie-anacron
yum remove bind
yum remove vsftpd
yum remove httpd
yum remove dovecot
yum remove squid
yum remove net-snmpd

vi /etc/sysctl.conf

net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.tcp_max_syn_backlog = 1280
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_timestamps = 0

audit rules /etc/audit/rules.d/audit.rules

sed -i "s/inet_interfaces = all/inet_interfaces = localhost/g" /etc/postfix/main.cf
echo "fs.suid_dumpable = 0" >> /etc/sysctl.d/98-CIS.conf
#3.1.2 Ensure packet redirect sending is disabled
echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.d/98-CIS.conf
echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.d/98-CIS.conf
#3.2.1 Ensure IP forwarding is disabled
echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.d/98-CIS.conf
echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.d/98-CIS.conf
#3.2.3 Ensure secure ICMP redirects are not accepted
echo "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.d/98-CIS.conf
echo "net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.d/98-CIS.conf
#3.2.4 Ensure suspicious packets are logged
echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.d/98-CIS.conf
echo "net.ipv4.conf.default.log_martians = 1" >> /etc/sysctl.d/98-CIS.conf
#4.2.4 Ensure permissions on all logfiles are configured
chmod -R g-wx,o-rwx /var/log/*
#5.1.2 Ensure permissions on /etc/crontab are configured
chown root:root /etc/crontab
chmod og-rwx /etc/crontab
#5.1.3 Ensure permissions on /etc/cron.hourly are configured
chown root:root /etc/cron.hourly
chmod og-rwx /etc/cron.hourly
#5.1.4 Ensure permissions on /etc/cron.daily are configured
chown root:root /etc/cron.daily
chmod og-rwx /etc/cron.daily
#5.15 Ensure permissions on /etc/cron.weekly are configured
chown root:root /etc/cron.weekly
chmod og-rwx /etc/cron.weekly
#5.1.6 Ensure permissions on /etc/cron.monthly are configured
chown root:root /etc/cron.monthly
chmod og-rwx /etc/cron.monthly
#5.1.7 Ensure permissions on /etc/cron.d are configured
chown root:root /etc/cron.d
chmod og-rwx /etc/cron.d
#5.1.8 Ensure at/cron is restricted to authorized users
#rm /etc/cron.deny
#rm /etc/at.deny
touch /etc/cron.allow
touch /etc/at.allow
chmod og-rwx /etc/cron.allow
chmod og-rwx /etc/at.allow
chown root:root /etc/cron.allow
chown root:root /etc/at.allow
#5.2.1 Ensure permissions on /etc/ssh/sshd_config are configured
chown root:root /etc/ssh/sshd_config
chmod og-rwx /etc/ssh/sshd_config
#5.2.4 Ensure SSH X11 forwarding is disabled
sed -i "s/X11Forwarding yes/X11Forwarding no/g" /etc/ssh/sshd_config
#5.2.5 Ensure SSH MaxAuthTries is set to 4 or less
echo "MaxAuthTries 4" >> /etc/ssh/sshd_config
#5.2.8 Ensure SSH root login is disabled
sed -i "s/PermitRootLogin prohibit-password/PermitRootLogin no/g" /etc/ssh/sshd_config
#5.2.10 Ensure SSH PermitUserEnvironment is disabled
echo "PermitUserEnvironment no" >> /etc/ssh/sshd_config
#5.2.11 Ensure only approved MAC algorithms are used
echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com" >> /etc/ssh/sshd_config
#5.2.12 Ensure SSH Idle Timeout Interval is configured
echo "ClientAliveInterval 300" >> /etc/ssh/sshd_config
echo "ClientAliveCountMax 3" >> /etc/ssh/sshd_config
#5.2.13 Ensure SSH LoginGraceTime is set to one minute or less
sed -i "s/LoginGraceTime 120/LoginGraceTime 60/g" /etc/ssh/sshd_config
#5.2.15 Ensure SSH warning banner is configured
echo "Banner /etc/issue" >> /etc/ssh/sshd_config
echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue

#Prevent Log In to Accounts With Empty Password
sed -i 's/\<nullok\>//g' /etc/pam.d/system-auth

#5.3.1 Ensure password creation requirements are configured


chmod 750 /bin/ping
chmod 750 /usr/bin/finger
chmod 750 /usr/bin/who
chmod 750 /usr/bin/w
chmod 750 /usr/bin/locate
chmod 750 /usr/bin/whereis
chmod 750 /sbin/ifconfig


sed -i "s/password requisite pam_pwquality.so retry=3/password requisite pam_pwquality.so try_first_pass retry=3/g" /etc/pam.d/common-password
sed -i "s/# minlen = 8/minlen =  14/g"  /etc/security/pwquality.conf
sed -i "s/# dcredit = 0/dcredit = -1/g" /etc/security/pwquality.conf
sed -i "s/# ucredit = 0/ucredit = -1/g"  /etc/security/pwquality.conf
sed -i "s/# ocredit = 0/ocredit = -1/g"  /etc/security/pwquality.conf
sed -i "s/# lcredit = 0/lcredit = -1/g"  /etc/security/pwquality.conf
#5.3.3 Ensure password reuse is limited
sed -i "s/try_first_pass sha512/try_first_pass sha512 remember=5/g" /etc/pam.d/common-password
#5.4.1.1 Ensure password expiration is 90 days or less
sed -i '/^PASS_MAX_DAYS/ c\PASS_MAX_DAYS\t90' /etc/login.defs
#5.4.1.2 Ensure minimum days between password changes is 7 or more
sed -i 's/^PASS_MIN_DAYS.*0/PASS_MIN_DAYS    7/g' /etc/login.defs
#5.4.1.4 Ensure inactive password lock is 30 days or less
useradd -D -f 30
#5.4.4 Ensure default user umask is 027 or more restrictive
echo "umask 027" >> /etc/profile
echo "umask 027" >> /etc/bash.bashrc
#remove duplicates from /etc/security/security.conf
#awk '!x[$0]++' /etc/security/limits.d/98-CIS.conf | tee  /etc/security/limits.d/98-CIS.conf
#cleanup any duplicates in CIS.conf
#awk '!x[$0]++' /etc/modprobe.d/CIS.conf | tee  /etc/modprobe.d/CIS.conf
#remove duplicates from /etc/sysctl.conf
#awk '!x[$0]++' /etc/sysctl.d/98-CIS.conf | tee /etc/sysctl.d/98-CIS.conf
#remove duplicates from /etc/ssh/sshd_config
#awk '!x[$0]++' /etc/ssh/sshd_config | tee /etc/ssh/sshd_config
