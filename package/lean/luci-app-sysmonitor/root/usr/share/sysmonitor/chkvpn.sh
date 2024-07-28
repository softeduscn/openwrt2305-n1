#!/bin/bash

[ -f /tmp/chkvpn.run ] && exit
[ ! -f /tmp/chkvpn.pid ] && echo 0 >/tmp/chkvpn.pid
[ "$(cat /tmp/chkvpn.pid)" != 0 ] && exit

touch /tmp/chkvpn.run
NAME=sysmonitor
APP_PATH=/usr/share/$NAME
SYSLOG='/var/log/sysmonitor.log'

echolog() {
	local d="$(date "+%Y-%m-%d %H:%M:%S")"
	echo -e "$d: $*" >>$SYSLOG
	number=$(cat $SYSLOG|wc -l)
	[ $number -gt 25 ] && sed -i '1,10d' $SYSLOG
}

uci_get_by_name() {
	local ret=$(uci get $1.$2.$3 2>/dev/null)
	echo ${ret:=$4}
}

uci_set_by_name() {
	uci set $1.$2.$3=$4 2>/dev/null
	uci commit $1
}

sys_exit() {
#	echolog "chkVPN is off."
	[ -f /tmp/chkvpn.run ] && rm -rf /tmp/chkvpn.run
	syspid=$(cat /tmp/chkvpn.pid)
	syspid=$((syspid-1))
	echo $syspid > /tmp/chkvpn.pid
	exit 0
}

chk_sign() {
	if [ -f /tmp/$1 ]; then
		rm -rf /tmp/$1
		$APP_PATH/sysapp.sh $2 &
	fi
}

if [ -f /tmp/firstrun ]; then
	echo "300=ntpd -n -q -p ntp.aliyun.com" >> /tmp/delay.sign
#	sed -i "/coremark/d" /etc/crontabs/root
#	crontab /etc/crontabs/root
	rm /tmp/firstrun
fi

#echolog "chkVPN is on."
syspid=$(cat /tmp/chkvpn.pid)
syspid=$((syspid+1))
echo $syspid > /tmp/chkvpn.pid
chknum=0
chksys=0
while [ "1" == "1" ]; do
	chknum=$((chknum+1))
	[ ! -f /tmp/test.chkvpn ] && touch /tmp/test.chkvpn
	prog='sysmonitor'
	for i in $prog
	do
		progsh=$i'.sh'
		progpid='/tmp/'$i'.pid'
		[ "$(pgrep -f $progsh|wc -l)" == 0 ] && echo 0 > $progpid
		[ ! -f $progpid ] && echo 0 > $progpid
		arg=$(cat $progpid)
		case $arg in
			0)
				[ "$(pgrep -f $progsh|wc -l)" != 0 ] && killall $progsh
				progrun='/tmp/'$i'.run'
				[ -f $progrun ] && rm $progrun
				[ -f $progpid ] && rm $progpid
				$APP_PATH/$progsh &
				;;
			1)
				#if [ "$arg" == "sysmonitor" ] && [ "$chknum" == 60 ]; then
				if [ "$chknum" -ge 60 ]; then
					chknum=0
					chksys=0
					if [ ! -f /tmp/test.$i ]; then	
						killall $progsh
					else
						rm /tmp/test.$i	
					fi
				fi
				;;
			*)
				chksys=$((chksys+1))
				if [ "$chksys" -ge 120 ]; then
					killall $progsh
					echo 0 > $progpid
					chksys=0
				fi
				;;
		esac
	done
	[ $(cat /tmp/delay.list|grep chkprog|wc -l) == 0 ] && $APP_PATH/sysapp.sh chkprog
	if [ -f /tmp/delay.sign ]; then
		while read i
		do
			prog=$(echo $i|cut -d'=' -f2)
			[ -n $(echo $prog|cut -d' ' -f2) ] && prog=$(echo $prog|cut -d' ' -f2)
			sed -i "/$prog/d" /tmp/delay.list
			echo $i >> /tmp/delay.list
		done < /tmp/delay.sign
		rm /tmp/delay.sign
	fi
	if [ -f /tmp/delay.list ]; then
		touch /tmp/delay.tmp
		while read line
		do
   			num=$(echo $line|cut -d'=' -f1)
			prog=$(echo $line|cut -d'=' -f2-)
			if [ "$num" -gt 0 ];  then
				num=$((num-1))
				tmp=$num'='$prog
				echo $tmp >> /tmp/delay.tmp
			else
			[ "$num" == 0 ] && $prog &
			fi
		done < /tmp/delay.list
		if [ -n "$(cat /tmp/delay.tmp)" ]; then
			mv /tmp/delay.tmp /tmp/delay.list
		else
			rm /tmp/delay.tmp
			rm /tmp/delay.list
		fi	
	fi
	if [ -f /tmp/ipv4.sign ]; then
		rm /tmp/ipv4.sign
		ipv4=$(ip -o -4 addr list br-lan | cut -d ' ' -f7 | cut -d'/' -f1)
		echo $ipv4 >/www/ip.html
	fi
	if [ -f /tmp/ipv6.sign ]; then
		rm /tmp/ipv6.sign	
		ipv6=$(ip -o -6 addr list br-lan | cut -d ' ' -f7 | cut -d'/' -f1 |head -n1)
		echo $ipv6 > /www/ip6.html
		echolog 'ip6='$ipv6
		$APP_PATH/sysapp.sh update_ddns &
	fi
	[ ! -n "$(pgrep -f next_vpn)" ] && [ -f /tmp/next_vpn.run ] && rm /tmp/next_vpn.run
#	[ -f /etc/init.d/lighttpd ] && [ -n "$(pgrep -f lighttpd)" ] && [ ! -n "$(pgrep -f uhttpd)" ] && /etc/init.d/uhttpd start
#	[ ! -n "$(pgrep -f uhttpd)" ] && /etc/init.d/uhttpd start
#	[ -f /etc/init.d/lighttpd ] && [ ! -n "$(pgrep -f lighttpd)" ] && {
#		/etc/init.d/lighttpd start
#		}
	dns=$(uci_get_by_name $NAME $NAME dns 'NULL')
	case $dns in
		SmartDNS)
			#[ "$(ps |grep -v grep|grep mosdns|wc -l)" != 0 ] && $APP_PATH/sysapp.sh setdns &
			[ -n "$(pgrep -f mosdns)" ] && $APP_PATH/sysapp.sh setdns &
			;;
		MosDNS)
			#[ "$(ps |grep -v grep|grep smartdns|wc -l)" != 0 ] && $APP_PATH/sysapp.sh setdns &
			[ -n "$(pgrep -f smartdns)" ] && $APP_PATH/sysapp.sh setdns &
			;;
		*)
			#[ "$(ps |grep -v grep|grep mosdns|wc -l)" != 0 ] && $APP_PATH/sysapp.sh setdns &
			#[ "$(ps |grep -v grep|grep smartdns|wc -l)" != 0 ] && $APP_PATH/sysapp.sh setdns &
			[ -n "$(pgrep -f mosdns)" ] && $APP_PATH/sysapp.sh setdns &
			[ -n "$(pgrep -f smartdns)" ] && $APP_PATH/sysapp.sh setdns &
			;;
	esac
	chk_sign nextvpn.sign next_vpn
	chk_sign getvpn.sign getvpn
	chk_sign makehost.sign makehost
	[ ! -f /tmp/chkvpn.run ] && sys_exit
	[ "$(cat /tmp/chkvpn.pid)" -gt 1 ] && sys_exit
	sleep 1
done
