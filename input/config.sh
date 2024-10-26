#!/bin/bash

BASEDIR=$(dirname $(readlink -f "$0"))
OUTDIR=$(dirname $BASEDIR)

cd $BASEDIR
echo "config auditbeat.yml"
cp auditbeat.yml /etc/auditbeat

echo "config audit-rules.conf"
audit_rule_path=/etc/auditbeat/audit.rules.d/audit-rules.conf
echo -e "-a never,exit -S all -F subj_type=pulseaudio_t -F subj_type=ntpd_t -F subj_type=cron_t\n"  > $audit_rule_path
echo -e "## Cron jobs fill the logs with stuff we normally don't want (works with SELinux) \n-a never,user -F subj_type=crond_t\n-a exit,never -F subj_type=crond_t\n-a never,user -F subj_type=cron_t\n-a exit,never -F subj_type=cron_t" >> $audit_rule_path


# Currently, this script intercepts all system calls, and you can customize the system calls and filters, ...
echo -e "\n-a always,exit -S all" >> $audit_rule_path

# delete previous audit records
echo "delete existing audit records"
rm /var/log/auditbeat/* > /dev/null 2>&1

# Create a new folder to record init information
echo "collect meta-information before system auditing"
folder=$OUTDIR/audit_out
rm -rf $folder
mkdir $folder
cd $folder

# Collect information for current processes running on the system 
mkdir procinfo
cd procinfo
ps -ef > general.txt
ps -eo pid > pid.txt
ps -eo comm > exe.txt
ps -eo args > args.txt
ps -eo ppid > ppid.txt

# Collect information for file descriptor
cd ../
mkdir fdinfo
cd fdinfo
for proc in $(ls /proc | grep '[0-9+]'); do
		touch $proc 1>/dev/null 
		ls -la /proc/$proc/fd > $proc 2>/dev/null
done

# Collect information for socket descriptor
cd ../
mkdir socketinfo
cd socketinfo
lsof -i -n -P > general.txt
cat general.txt | awk '{print $6}' > device.txt
cat general.txt | awk '{print $9}' > name.txt

# Start auditbeat
service auditbeat restart
cd ../
