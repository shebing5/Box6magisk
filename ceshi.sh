#!/system/bin/sh

# Define paths and variables
module_dir="/data/adb/modules/box5"
[ -n "$(magisk -v | grep lite)" ] && module_dir=/data/adb/lite_modules/box5
scripts=$(realpath $0)
scripts_dir=$(dirname ${scripts})
box_path="/data/adb/box_bll"
run_path="${box_path}/run"
pid_file="${run_path}/clash.pid"
tunid_file="${run_path}/tun.id"
clash_path="${box_path}/clash"
bin_name="clash"
redir_port="7891"
tproxy_port="1536"
clash_dns_port="1053"
clash_dns_listen="0.0.0.0:${clash_dns_port}"
clash_fake_ip_range="28.0.0.1/8"
tun_device="tun0"
sub_enable=false
subscribe="http://127.0.0.1"
nodes=''
box_user_group="root:net_admin"
bin_name_list=("sing-box" "clash" "xray" "v2ray")
ipv6="disable"
phy_if="wlan0"
proxy_method="APP"
proxy_mode="blacklist"
user_packages_list=()
ap_list=("wlan+" "eth+" "ap+" "rndis+")
ignore_out_list=()
intranet=(0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 192.0.0.0/24 192.0.2.0/24 192.88.99.0/24 192.168.0.0/16 198.51.100.0/24 203.0.113.0/24 224.0.0.0/4 240.0.0.0/4 255.255.255.255/32)
intranet6=(::/128 ::1/128 ::ffff:0:0/96 100::/64 64:ff9b::/96 2001::/32 2001:10::/28 2001:20::/28 2001:db8::/32 2002::/16 fe80::/10 ff00::/8)

# Logging function
log() {
    export TZ=Asia/Shanghai
    now=$(date +"[%Y-%m-%d %H:%M:%S %Z]")
    case $1 in
        Info)
            [ -t 1 ] && echo -e "\033[1;32m${now} [Info]: $2\033[0m" || echo "${now} [Info]: $2"
            ;;
        Warn)
            [ -t 1 ] && echo -e "\033[1;33m${now} [Warn]: $2\033[0m" || echo "${now} [Warn]: $2"
            ;;
        Error)
            [ -t 1 ] && echo -e "\033[1;31m${now} [Error]: $2\033[0m" || echo "${now} [Error]: $2"
            ;;
        *)
            [ -t 1 ] && echo -e "\033[1;30m${now} [$1]: $2\033[0m" || echo "${now} [$1]: $2"
            ;;
    esac
}

# Wait until user login
wait_until_login(){
    local test_file="/sdcard/Android/.BOX5TEST"
    true > "$test_file"
    while [ ! -f "$test_file" ] ; do
        true > "$test_file"
        sleep 1
    done
    rm "$test_file"
}

# Start service
start_service() {
    # Implement start service logic here
    log Info "Starting service..."
}

# Stop service
stop_service() {
    # Implement stop service logic here
    log Info "Stopping service..."
}

# Monitor service
monitor_service() {
    # Implement monitor service logic here
    log Info "Monitoring service..."
}

# Tproxy setup
setup_tproxy() {
    # Implement tproxy setup logic here
    log Info "Setting up TPROXY..."
}

# Inotify service control
inotify_service_control() {
    # Implement inotify service control logic here
    log Info "Inotify service control..."
}

# Main script execution
main() {
    wait_until_login
    mkdir -p ${run_path}
    rm ${pid_file}

    if [ ! -f ${box_path}/manual ] && [ ! -f ${module_dir}/disable ] ; then
        mv ${run_path}/run.log ${run_path}/run.log.bak
        mv ${run_path}/run_error.log ${run_path}/run_error.log.bak

        start_service
        setup_tproxy
    fi

    monitor_service
}

main "$@"
# Function to check permissions and set capabilities
check_permission() {
    if which ${bin_name} | grep -q "/system/bin/" ; then
        box_user=$(echo ${box_user_group} | awk -F ':' '{print $1}')
        box_group=$(echo ${box_user_group} | awk -F ':' '{print $2}')
        box_user_id=$(id -u ${box_user})
        box_group_id=$(id -g ${box_group})
        [ ${box_user_id} ] && [ ${box_group_id} ] || \
        (box_user_group="root:net_admin" && log Error "${box_user_group} error, use root:net_admin instead.")
        bin_path=$(which ${bin_name})
        chown ${box_user_group} ${bin_path}
        chmod 0700 ${bin_path}
        if [ "${box_user_id}" != "0" ] || [ "${box_group_id}" != "3005" ] ; then
            setcap 'cap_net_admin,cap_net_raw,cap_net_bind_service+ep' ${bin_path} || \
            (box_user_group="root:net_admin" && log Error "setcap authorization failed, you may need libcap package.")
        fi
        chown -R ${box_user_group} ${box_path}
        return 0
    elif [ -f ${bin_path} ] ; then
        box_user_group="root:net_admin"
        chown ${box_user_group} ${bin_path}
        chmod 0700 ${bin_path}
        chown -R ${box_user_group} ${box_path}
        return 0
    else
        return 1
    fi
}

# Function to start the binary
start_bin() {
    ulimit -SHn 1000000
    case "${bin_name}" in
        sing-box)
            if ${bin_path} check -D ${box_path}/${bin_name} > ${run_path}/check.log 2>&1 ; then
                return 0
            else
                return 1
            fi
            ;;
        clash)
            if [ "$sub_enable" = true ]; then
                sed -i 's#url: ".*"#url: "'"${subscribe}"'"#' ${clash_path}/config.yaml
            fi
            if ${bin_path} -t -d ${box_path}/${bin_name} > ${run_path}/check.log 2>&1 ; then
                return 0
            else
                return 1
            fi
            ;;
        xray)
            if ${bin_path} -test -confdir ${box_path}/${bin_name} > ${run_path}/check.log 2>&1 ; then
                return 0
            else
                return 1
            fi
            ;;
        v2ray)
            if ${bin_path} test -d ${box_path}/${bin_name} > ${run_path}/check.log 2>&1 ; then
                return 0
            else
                return 1
            fi
            ;;
        *)
            log Error "$1 core error, it must be one of ${bin_name_list[*]}"
            return 2
            ;;
    esac
}

# Function to wait for the binary to listen
wait_bin_listen() {
    wait_count=0
    bin_pid=$(busybox pidof ${bin_name})
    find_netstat_path && \
    check_bin_cmd="netstat -tnulp | grep -q ${bin_name}" || \
    check_bin_cmd="ls -lh /proc/${bin_pid}/fd | grep -q socket"
    while [ ${bin_pid} ] && ! eval "${check_bin_cmd}" && [ ${wait_count} -lt 100 ] ; do
        sleep 1 ; wait_count=$((${wait_count} + 1))
    done
    if [ ${bin_pid} ] && eval "${check_bin_cmd}" ; then
        return 0
    else
        return 1
    fi
}

# Function to display the binary status
display_bin_status() {
    if bin_pid=$(busybox pidof ${bin_name}) ; then
        log Info "${bin_name} has started with the $(stat -c %U:%G /proc/${bin_pid}) user group."
        log Info "${bin_name} service is running. ( PID: ${bin_pid} )"
        log Info "${bin_name} memory usage: $(cat /proc/${bin_pid}/status | grep -w VmRSS | awk '{print $2$3}')"
        log Info "${bin_name} cpu usage: $((/system/bin/ps -eo %CPU,NAME | grep ${bin_name} | awk '{print $1"%"}') 2> /dev/null || dumpsys cpuinfo | grep ${bin_name} | awk '{print $1}')"
        log Info "${bin_name} running time: $(busybox ps -o comm,etime | grep ${bin_name} | awk '{print $2}')"
        echo -n ${bin_pid} > ${pid_file}
        return 0
    else
        log Warn "${bin_name} service is stopped."
        return 1
    fi
}

# Function to start the service
start_service() {
    if check_permission ; then
        if [ "${proxy_method}" = "APP" ] ; then
            log Info "Run the proxy through an external app"
            sysctl net.ipv4.ip_forward=1 >/dev/null 2>&1
            iptables  -I FORWARD -o tun+ -j ACCEPT
            iptables  -I FORWARD -i tun+ -j ACCEPT
            return 0
        fi
        log Info "${bin_name} will be started with the ${box_user_group} user group."
        [ "${proxy_method}" != "TPROXY" ] && create_tun_link
        if start_bin && wait_bin_listen ; then
            return 0
        else
            log Error "Failed to start ${bin_name}."
            return 1
        fi
    else
        log Error "missing ${bin_name} core, please download and place it in the ${box_path}/bin/ directory"
        return 2
    fi
}

# Function to stop the service
stop_service() {
    if [ "${proxy_method}" = "APP" ] ; then
        pkill -f "${scripts_dir}/monitor.service" -9
        log Info "Turn off proxies through external apps"
        sysctl net.ipv4.ip_forward=0 >/dev/null 2>&1
        iptables  -D FORWARD -o tun+ -j ACCEPT
        iptables  -D FORWARD -i tun+ -j ACCEPT
        iptables  -t nat -D POSTROUTING -o tun+ -j MASQUERADE
        ip rule del from all table main pref 17999 >/dev/null 2>&1
        ip rule del from all iif ${phy_if} table $(cat ${tunid_file}) pref 17998 >/dev/null 2>&1
        rm -f ${tunid_file} >> /dev/null 2>&1
        log Info "APP proxy service stopped."
        return 0
    fi
    if display_bin_status ; then
        log Warn "stopping ${bin_name} service."
        kill $(cat ${pid_file}) || killall ${bin_name}
        forward -D >> /dev/null 2>&1
        sleep 1
        display_bin_status
    fi
    rm -f ${pid_file} >> /dev/null 2>&1
}

# Function to setup TPROXY
setup_tproxy() {
    if [ "${proxy_method}" = "APP" ] ; then
        return 0
    fi

    if [ "${proxy_mode}" = "core" ] ; then
        return 0
    fi

    start_tproxy() {
        if [ "${iptables}" = "ip6tables -w 100" ] ; then
            ip -6 route add local default dev lo table ${id}
        else
            ip route add local default dev lo table ${id}
        fi

        ${iptables} -t mangle -N BOX_EXTERNAL
        ${iptables} -t mangle -F BOX_EXTERNAL

        if [ "${bin_name}" = "clash" ] ; then
            ${iptables} -t mangle -A BOX_EXTERNAL -p udp --dport 53 -j TPROXY --on-port ${tproxy_port} --tproxy-mark ${id}
        fi

        ${iptables} -t mangle -A BOX_EXTERNAL -p tcp -i lo -j TPROXY --on-port ${tproxy_port} --tproxy-mark ${id}
        ${iptables} -t mangle -A BOX_EXTERNAL -p udp -i lo -j TPROXY --on-port ${tproxy_port} --tproxy-mark ${id}

        if [ "${ap_list}" != "" ] ; then
            for ap in ${ap_list[@]} ; do
                ${iptables} -t mangle -A BOX_EXTERNAL -p tcp -i ${ap} -j TPROXY --on-port ${tproxy_port} --tproxy-mark ${id}
                ${iptables} -t mangle -A BOX_EXTERNAL -p udp -i ${ap} -j TPROXY --on-port ${tproxy_port} --tproxy-mark ${id}
            done
            log Info "${ap_list[*]} transparent proxy."
        fi

        ${iptables} -t mangle -I PREROUTING -j BOX_EXTERNAL

        ${iptables} -t mangle -N BOX_LOCAL
        ${iptables} -t mangle -F BOX_LOCAL

        if [ "${ignore_out_list}" != "" ] ; then
            for ignore in ${ignore_out_list[@]} ; do
                ${iptables} -t mangle -A BOX_LOCAL -o ${ignore} -j RETURN
            done
            log Info "${ignore_out_list[*]} ignore transparent proxy."
        fi

        if [ "${bin_name}" = "clash" ] ; then
            ${iptables} -t mangle -A BOX_LOCAL -p udp --dport 53 -j TPROXY --on-port ${tproxy_port} --tproxy-mark ${id}
        fi

        ${iptables} -t mangle -I BOX_LOCAL -m owner --uid-owner ${box_user} --gid-owner ${box_group} -j RETURN

        if [ "${proxy_mode}" = "blacklist" ] ; then
            for uid in ${uid_list[@]} ; do
                ${iptables} -t mangle -A BOX_LOCAL -m owner --uid-owner ${uid} -j RETURN
            done
        elif [ "${proxy_mode}" = "whitelist" ] ; then
            ${iptables} -t mangle -A BOX_LOCAL -m owner --uid-owner ${box_user} --gid-owner ${box_group} -j RETURN
            for uid in ${uid_list[@]} ; do
                ${iptables} -t mangle -A BOX_LOCAL -m owner --uid-owner ${uid} -j TPROXY --on-port ${tproxy_port} --tproxy-mark ${id}
            done
            log Info "proxy mode: ${proxy_mode}, ${user_packages_list[*]} transparent proxy."
        else
            ${iptables} -t mangle -A BOX_LOCAL -m owner --uid-owner ${box_user} --gid-owner ${box_group} -j RETURN
            log Info "transparent proxy for all apps."
        fi

        ${iptables} -t mangle -I OUTPUT -j BOX_LOCAL

        ${iptables} -t mangle -N DIVERT
        ${iptables} -t mangle -F DIVERT

        ${iptables} -t mangle -A DIVERT -j MARK --set-mark ${id}
        ${iptables} -t mangle -A DIVERT -j ACCEPT

        ${iptables} -t mangle -I PREROUTING -p tcp -m socket -j DIVERT

        if [ "${iptables}" = "ip6tables -w 100" ] ; then
            ${iptables} -A OUTPUT -d ::1 -p tcp -m owner --uid-owner ${box_user} --gid-owner ${box_group} -m tcp --dport ${tproxy_port} -j REJECT
        else
            ${iptables} -A OUTPUT -d 127.0.0.1 -p tcp -m owner --uid-owner ${box_user} --gid-owner ${box_group} -m tcp --dport ${tproxy_port} -j REJECT
        fi

        if [ "${bin_name}" = "clash" ] && [ "${iptables}" = "iptables -w 100" ] ; then
            ${iptables} -t nat -I PREROUTING -d ${clash_fake_ip_range} -p icmp -j DNAT --to-destination 127.0.0.1
        fi
    }

    stop_tproxy() {
        if [ "${iptables}" = "ip6tables -w 100" ] ; then
            ip -6 route flush table ${id}
        else
            ip route flush table ${id}
        fi

        ${iptables} -t mangle -D PREROUTING -j BOX_EXTERNAL
        ${iptables} -t mangle -D PREROUTING -p tcp -m socket -j DIVERT
        ${iptables} -t mangle -D OUTPUT -j BOX_LOCAL

        ${iptables} -t mangle -F BOX_EXTERNAL
        ${iptables} -t mangle -X BOX_EXTERNAL

        ${iptables} -t mangle -F BOX_LOCAL
        ${iptables} -t mangle -X BOX_LOCAL

        ${iptables} -t mangle -F DIVERT
        ${iptables} -t mangle -X DIVERT

        if [ "${iptables}" = "ip6tables -w 100" ] ; then
            ${iptables} -D OUTPUT -d ::1 -p tcp -m owner --uid-owner 0 --gid-owner 3005 -m tcp --dport ${tproxy_port} -j REJECT
        else
            ${iptables} -D OUTPUT -d 127.0.0.1 -p tcp -m owner --uid-owner 0 --gid-owner 3005 -m tcp --dport ${tproxy_port} -j REJECT
        fi
    }

    start_tproxy
}

# Function to monitor the service
monitor_service() {
    wait_for_tun_device() {
        until grep -q -E "tun[0-9]" /data/misc/net/rt_tables; do
            sleep 2
        done
    }

    get_tun_id() {
        grep -E "tun[0-9]" /data/misc/net/rt_tables | awk '{print $1}' > "$tunid_file"
        cat "$tunid_file"
    }

    ip_rule() {
        ip rule "$1" from all iif "$phy_if" table "$2" pref 17998
    }

    check_tun_device() {
        if ip rule | grep -q "from all iif $phy_if lookup $1"; then
            log Warn "The tun device has been lost and is awaiting recovery."
            return 1
        fi
    }

    wait_for_tun_device
    tunid=$(get_tun_id)
    ip_rule add $tunid >> /dev/null 2>&1
    while true; do
        if ! check_tun_device "$tunid"; then
            ip_rule del $tunid >> /dev/null 2>&1
            wait_for_tun_device
            tunid=$(get_tun_id)
            log Info "The tun device has been reacquired, new id: "$tunid
            ip_rule add $tunid >> /dev/null 2>&1
        fi
        sleep 3
    done
}

# Function to control inotify service
inotify_service_control() {
    service_control() {
        if [ ! -f ${box_path}/manual ] ; then
            if [ "${monitor_file}" = "disable" ] ; then
                if [ "${events}" = "d" ] ; then
                    start_service
                    setup_tproxy
                elif [ "${events}" = "n" ] ; then
                    stop_tproxy
                    stop_service
                fi
            fi
        fi
    }

    mkdir -p ${run_path}
    service_control
}
# Function to create TUN link
create_tun_link() {
    mkdir -p /dev/net
    [ ! -L /dev/net/tun ] && ln -s /dev/tun /dev/net/tun
}

# Function to forward traffic
forward() {
    iptables -w 100 $1 FORWARD -o ${tun_device} -j ACCEPT
    iptables -w 100 $1 FORWARD -i ${tun_device} -j ACCEPT
    ip6tables -w 100 $1 FORWARD -o ${tun_device} -j ACCEPT
    ip6tables -w 100 $1 FORWARD -i ${tun_device} -j ACCEPT
}

# Function to find netstat path
find_netstat_path() {
    [ -f /system/bin/netstat ] && alias netstat="/system/bin/netstat" && return 0
    [ -f /system/xbin/netstat ] && alias netstat="/system/xbin/netstat" && return 0
    return 1
}

# Function to control inotify service
inotify_service_control() {
    service_control() {
        if [ ! -f ${box_path}/manual ] ; then
            if [ "${monitor_file}" = "disable" ] ; then
                if [ "${events}" = "d" ] ; then
                    start_service
                    setup_tproxy
                elif [ "${events}" = "n" ] ; then
                    stop_tproxy
                    stop_service
                fi
            fi
        fi
    }

    mkdir -p ${run_path}
    service_control
}

# Main script execution
main() {
    wait_until_login
    mkdir -p ${run_path}
    rm ${pid_file}

    if [ ! -f ${box_path}/manual ] && [ ! -f ${module_dir}/disable ] ; then
        mv ${run_path}/run.log ${run_path}/run.log.bak
        mv ${run_path}/run_error.log ${run_path}/run_error.log.bak

        start_service
        setup_tproxy
    fi

    monitor_service
}

main "$@"
# Function to handle TPROXY setup
setup_tproxy() {
    if [ "${proxy_method}" = "APP" ] ; then
        return 0
    fi

    if [ "${proxy_mode}" = "core" ] ; then
        return 0
    fi

    start_tproxy() {
        if [ "${iptables}" = "ip6tables -w 100" ] ; then
            ip -6 route add local default dev lo table ${id}
        else
            ip route add local default dev lo table ${id}
        fi

        ${iptables} -t mangle -N BOX_EXTERNAL
        ${iptables} -t mangle -F BOX_EXTERNAL

        if [ "${bin_name}" = "clash" ] ; then
            ${iptables} -t mangle -A BOX_EXTERNAL -p udp --dport 53 -j TPROXY --on-port ${tproxy_port} --tproxy-mark ${id}
        fi

        ${iptables} -t mangle -A BOX_EXTERNAL -p tcp -i lo -j TPROXY --on-port ${tproxy_port} --tproxy-mark ${id}
        ${iptables} -t mangle -A BOX_EXTERNAL -p udp -i lo -j TPROXY --on-port ${tproxy_port} --tproxy-mark ${id}

        if [ "${ap_list}" != "" ] ; then
            for ap in ${ap_list[@]} ; do
                ${iptables} -t mangle -A BOX_EXTERNAL -p tcp -i ${ap} -j TPROXY --on-port ${tproxy_port} --tproxy-mark ${id}
                ${iptables} -t mangle -A BOX_EXTERNAL -p udp -i ${ap} -j TPROXY --on-port ${tproxy_port} --tproxy-mark ${id}
            done
            log Info "${ap_list[*]} transparent proxy."
        fi

        ${iptables} -t mangle -I PREROUTING -j BOX_EXTERNAL

        ${iptables} -t mangle -N BOX_LOCAL
        ${iptables} -t mangle -F BOX_LOCAL

        if [ "${ignore_out_list}" != "" ] ; then
            for ignore in ${ignore_out_list[@]} ; do
                ${iptables} -t mangle -A BOX_LOCAL -o ${ignore} -j RETURN
            done
            log Info "${ignore_out_list[*]} ignore transparent proxy."
        fi

        if [ "${bin_name}" = "clash" ] ; then
            ${iptables} -t mangle -A BOX_LOCAL -p udp --dport 53 -j TPROXY --on-port ${tproxy_port} --tproxy-mark ${id}
        fi

        ${iptables} -t mangle -I BOX_LOCAL -m owner --uid-owner ${box_user} --gid-owner ${box_group} -j RETURN

        if [ "${proxy_mode}" = "blacklist" ] ; then
            for uid in ${uid_list[@]} ; do
                ${iptables} -t mangle -A BOX_LOCAL -m owner --uid-owner ${uid} -j RETURN
            done
        elif [ "${proxy_mode}" = "whitelist" ] ; then
            ${iptables} -t mangle -A BOX_LOCAL -m owner --uid-owner ${box_user} --gid-owner ${box_group} -j RETURN
            for uid in ${uid_list[@]} ; do
                ${iptables} -t mangle -A BOX_LOCAL -m owner --uid-owner ${uid} -j TPROXY --on-port ${tproxy_port} --tproxy-mark ${id}
            done
            log Info "proxy mode: ${proxy_mode}, ${user_packages_list[*]} transparent proxy."
        else
            ${iptables} -t mangle -A BOX_LOCAL -m owner --uid-owner ${box_user} --gid-owner ${box_group} -j RETURN
            log Info "transparent proxy for all apps."
        fi

        ${iptables} -t mangle -I OUTPUT -j BOX_LOCAL

        ${iptables} -t mangle -N DIVERT
        ${iptables} -t mangle -F DIVERT

        ${iptables} -t mangle -A DIVERT -j MARK --set-mark ${id}
        ${iptables} -t mangle -A DIVERT -j ACCEPT

        ${iptables} -t mangle -I PREROUTING -p tcp -m socket -j DIVERT

        if [ "${iptables}" = "ip6tables -w 100" ] ; then
            ${iptables} -A OUTPUT -d ::1 -p tcp -m owner --uid-owner ${box_user} --gid-owner ${box_group} -m tcp --dport ${tproxy_port} -j REJECT
        else
            ${iptables} -A OUTPUT -d 127.0.0.1 -p tcp -m owner --uid-owner ${box_user} --gid-owner ${box_group} -m tcp --dport ${tproxy_port} -j REJECT
        fi

        if [ "${bin_name}" = "clash" ] && [ "${iptables}" = "iptables -w 100" ] ; then
            ${iptables} -t nat -I PREROUTING -d ${clash_fake_ip_range} -p icmp -j DNAT --to-destination 127.0.0.1
        fi
    }

    stop_tproxy() {
        if [ "${iptables}" = "ip6tables -w 100" ] ; then
            ip -6 route flush table ${id}
        else
            ip route flush table ${id}
        fi

        ${iptables} -t mangle -D PREROUTING -j BOX_EXTERNAL
        ${iptables} -t mangle -D PREROUTING -p tcp -m socket -j DIVERT
        ${iptables} -t mangle -D OUTPUT -j BOX_LOCAL

        ${iptables} -t mangle -F BOX_EXTERNAL
        ${iptables} -t mangle -X BOX_EXTERNAL

        ${iptables} -t mangle -F BOX_LOCAL
        ${iptables} -t mangle -X BOX_LOCAL

        ${iptables} -t mangle -F DIVERT
        ${iptables} -t mangle -X DIVERT

        if [ "${iptables}" = "ip6tables -w 100" ] ; then
            ${iptables} -D OUTPUT -d ::1 -p tcp -m owner --uid-owner 0 --gid-owner 3005 -m tcp --dport ${tproxy_port} -j REJECT
        else
            ${iptables} -D OUTPUT -d 127.0.0.1 -p tcp -m owner --uid-owner 0 --gid-owner 3005 -m tcp --dport ${tproxy_port} -j REJECT
        fi
    }

    start_tproxy
}

# Function to monitor the service
monitor_service() {
    wait_for_tun_device() {
        until grep -q -E "tun[0-9]" /data/misc/net/rt_tables; do
            sleep 2
        done
    }

    get_tun_id() {
        grep -E "tun[0-9]" /data/misc/net/rt_tables | awk '{print $1}' > "$tunid_file"
        cat "$tunid_file"
    }

    ip_rule() {
        ip rule "$1" from all iif "$phy_if" table "$2" pref 17998
    }

    check_tun_device() {
        if ip rule | grep -q "from all iif $phy_if lookup $1"; then
            log Warn "The tun device has been lost and is awaiting recovery."
            return 1
        fi
    }

    wait_for_tun_device
    tunid=$(get_tun_id)
    ip_rule add $tunid >> /dev/null 2>&1
    while true; do
        if ! check_tun_device "$tunid"; then
            ip_rule del $tunid >> /dev/null 2>&1
            wait_for_tun_device
            tunid=$(get_tun_id)
            log Info "The tun device has been reacquired, new id: "$tunid
            ip_rule add $tunid >> /dev/null 2>&1
        fi
        sleep 3
    done
}

# Function to control inotify service
inotify_service_control() {
    service_control() {
        if [ ! -f ${box_path}/manual ] ; then
            if [ "${monitor_file}" = "disable" ] ; then
                if [ "${events}" = "d" ] ; then
                    start_service
                    setup_tproxy
                elif [ "${events}" = "n" ] ; then
                    stop_tproxy
                    stop_service
                fi
            fi
        fi
    }

    mkdir -p ${run_path}
    service_control
}

main "$@"