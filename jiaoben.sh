#!/system/bin/sh

# 设置环境变量
export PATH="/data/adb/magisk:/data/adb/ksu/bin:$PATH:/data/data/com.termux/files/usr/bin:/system/xbin:/system/bin"

# 脚本路径和目录
scripts=$(realpath $0)
scripts_dir=$(dirname ${scripts})

# 配置变量（来自 box.config）
bin_name="clash"

redir_port="7891"
tproxy_port="1536"
clash_dns_port="1053"
clash_dns_listen="0.0.0.0:${clash_dns_port}"
clash_fake_ip_range="28.0.0.1/8"
tun_device="tun0"

# 启用 clash 订阅配置
sub_enable=false
subscribe="http://0.0.0.0"
nodes=''

box_user_group="root:net_admin"
bin_name_list=("sing-box" "clash" "xray" "v2ray")
box_path="/data/adb/box_bll"
bin_path="${box_path}/bin/${bin_name}"
run_path="${box_path}/run"
pid_file="${run_path}/${bin_name}.pid"
tunid_file="${run_path}/tun.id"
clash_path="${box_path}/clash"

intranet=(0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 192.0.0.0/24 192.0.2.0/24 192.88.99.0/24 192.168.0.0/16 198.51.100.0/24 203.0.113.0/24 224.0.0.0/4 240.0.0.0/4 255.255.255.255/32)
intranet6=(::/128 ::1/128 ::ffff:0:0/96 100::/64 64:ff9b::/96 2001::/32 2001:10::/28 2001:20::/28 2001:db8::/32 2002::/16 fe80::/10 ff00::/8)

ipv6="disable"

phy_if="wlan0" # APP模式需设置出口网卡名称
proxy_method="TPROXY"
# REDIRECT: TCP only / TPROXY: TCP + UDP / MIXED: REDIRECT TCP + TUN UDP / APP: TUN

proxy_mode="blacklist"
# blacklist / whitelist / core
user_packages_list=()
# Android User:Package Name, 例如：
# user_packages_list=("0:com.android.captiveportallogin" "10:com.tencent.mm")

ap_list=("wlan+" "eth+" "ap+" "rndis+")
ignore_out_list=()


# 添加新的全局变量
network_interfaces=()
active_interface=""
network_mode="" # wifi/mobile/ethernet
ipset_rules="box_rules"

# 启用 QUIC 支持的标志
enable_quic=true

# 日志函数
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


# 检查权限
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
      # setcap 已被弃用，因为它不支持 /system/bin 目录之外的二进制文件
      setcap 'cap_net_admin,cap_net_raw,cap_net_bind_service+ep' ${bin_path} || \
      (box_user_group="root:net_admin" && log Error "setcap 授权失败，您可能需要 libcap 包。")
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

# 启动核心程序
start_bin() {
  ulimit -SHn 1000000
  case "${bin_name}" in
    sing-box)
      if ${bin_path} check -D ${box_path}/${bin_name} > ${run_path}/check.log 2>&1 ; then
        log Info "正在启动 ${bin_name} 服务。"
        nohup busybox setuidgid ${box_user_group} ${bin_path} run -D ${box_path}/${bin_name} > /dev/null 2> ${run_path}/error_${bin_name}.log &
        echo -n $! > ${pid_file}
        return 0
      else
        log Error "配置检查失败，请检查 ${run_path}/check.log 文件。"
        return 1
      fi
      ;;
    clash)
      if [ "$sub_enable" = true ]; then
        if [ -n "$nodes" ]; then
          echo "$nodes" > ${clash_path}/proxy_providers/subscribe.yaml
        fi
        sed -i 's#url: ".*"#url: "'"${subscribe}"'"#' ${clash_path}/config.yaml
      fi
      # 如果启用 QUIC
      if [ "$enable_quic" = true ]; then
        export GOMAXPROCS=$(nproc)
        export CLASH_EXPERIMENT_QUIC=true  # 启用 QUIC 支持的环境变量
      fi
      if ${bin_path} -t -d ${box_path}/${bin_name} > ${run_path}/check.log 2>&1 ; then
        log Info "正在启动 ${bin_name} 服务。"
        nohup busybox setuidgid ${box_user_group} ${bin_path} -d ${box_path}/${bin_name} > ${box_path}/${bin_name}/${bin_name}_$(date +%Y%m%d%H%M).log 2> ${run_path}/error_${bin_name}.log &
        echo -n $! > ${pid_file}
        return 0
      else
        log Error "配置检查失败，请检查 ${run_path}/check.log 文件。"
        return 1
      fi
      ;;
    xray)
      if ${bin_path} -test -confdir ${box_path}/${bin_name} > ${run_path}/check.log 2>&1 ; then
        log Info "正在启动 ${bin_name} 服务。"
        nohup busybox setuidgid ${box_user_group} ${bin_path} -confdir ${box_path}/${bin_name} > /dev/null 2> ${run_path}/error_${bin_name}.log &
        echo -n $! > ${pid_file}
        return 0
      else
        log Error "配置检查失败，请检查 ${run_path}/check.log 文件。"
        return 1
      fi
      ;;
    v2ray)
      if ${bin_path} test -d ${box_path}/${bin_name} > ${run_path}/check.log 2>&1 ; then
        log Info "正在启动 ${bin_name} 服务。"
        nohup busybox setuidgid ${box_user_group} ${bin_path} run -d ${box_path}/${bin_name} > /dev/null 2> ${run_path}/error_${bin_name}.log &
        echo -n $! > ${pid_file}
        return 0
      else
        log Error "配置检查失败，请检查 ${run_path}/check.log 文件。"
        return 1
      fi
      ;;
    *)
      log Error "$1 核心错误，它必须是 ${bin_name_list[*]} 之一"
      return 2
      ;;
  esac
}

# 查找 netstat 路径
find_netstat_path() {
  [ -f /system/bin/netstat ] && alias netstat="/system/bin/netstat" && return 0
  [ -f /system/xbin/netstat ] && alias netstat="/system/xbin/netstat" && return 0
  return 1
}

# 等待核心程序监听
wait_bin_listen() {
  wait_count=0
  bin_pid=$(busybox pidof ${bin_name})
  # 检查 netstat 命令是否可用
  if command -v netstat >/dev/null 2>&1; then
    find_netstat_path && \
    check_bin_cmd="netstat -tnulp | grep -q ${bin_name}" || \
    check_bin_cmd="ls -lh /proc/${bin_pid}/fd | grep -q socket"
  else
    check_bin_cmd="ls -lh /proc/${bin_pid}/fd | grep -q socket"
  fi
  while [ ${bin_pid} ] && ! eval "${check_bin_cmd}" && [ ${wait_count} -lt 100 ] ; do
    sleep 1 ; wait_count=$((${wait_count} + 1))
    bin_pid=$(busybox pidof ${bin_name})
  done
  if [ ${bin_pid} ] && eval "${check_bin_cmd}" ; then
    return 0
  else
    return 1
  fi
}

# 显示核心程序状态
display_bin_status() {
  if bin_pid=$(busybox pidof ${bin_name}) ; then
    log Info "${bin_name} 已以 $(stat -c %U:%G /proc/${bin_pid}) 用户组启动。"
    log Info "${bin_name} 服务正在运行。 ( PID: ${bin_pid} )"
    log Info "${bin_name} 内存使用情况: $(cat /proc/${bin_pid}/status | grep -w VmRSS | awk '{print $2$3}')"
    log Info "${bin_name} CPU 使用率: $( ( /system/bin/ps -eo %CPU,NAME | grep ${bin_name} | awk '{print $1"%"}' ) 2> /dev/null || ( dumpsys cpuinfo | grep ${bin_name} | awk '{print $1}' ) )"
    log Info "${bin_name} 运行时间: $(busybox ps -o comm,etime | grep ${bin_name} | awk '{print $2}')"
    echo -n ${bin_pid} > ${pid_file}
    return 0
  else
    log Warn "${bin_name} 服务已停止。"
    return 1
  fi
}

# 启动服务
start_service() {
  if check_permission ; then
    if [ "${proxy_method}" = "APP" ] ; then
      log Info "通过外部应用运行代理"
      sudo sysctl net.ipv4.ip_forward=1 >/dev/null 2>&1
      iptables  -I FORWARD -o tun+ -j ACCEPT
      iptables  -I FORWARD -i tun+ -j ACCEPT
      iptables  -t nat -A POSTROUTING -o tun+ -j MASQUERADE
      ip rule add from all table main pref 17999
      log Info "转发代理已启动。"
      return 0
    fi

    # 新增：在启动服务前清理可能干扰的iptables规则
    log Info "清理可能干扰的 iptables 规则。"
    tproxy_control disable >> ${run_path}/run.log 2>> ${run_path}/run_error.log

    log Info "${bin_name} 将以 ${box_user_group} 用户组启动。"
    [ "${proxy_method}" != "TPROXY" ] && create_tun_link
    start_bin
    if wait_bin_listen ; then
      log Info "${bin_name} 服务正在运行。 ( PID: $(cat ${pid_file}) )"
      probe_tun_device && forward -I
      # 启动服务后设置iptables规则
      tproxy_control enable >> ${run_path}/run.log 2>> ${run_path}/run_error.log
      
      # 新增: 定期清理连接跟踪表
      (while true; do sleep 3600; clean_conntrack; done) &
      
      # 新增: 监控 TUN 设备
      [ "${proxy_method}" != "TPROXY" ] && monitor_service &
      
      return 0
    else
      if bin_pid=$(pidof ${bin_name}) ; then
        log Warn "${bin_name} 服务正在运行，但可能未监听。 ( PID: ${bin_pid} )"
        probe_tun_device && forward -I  
        # 启动服务后设置iptables规则
        tproxy_control enable >> ${run_path}/run.log 2>> ${run_path}/run_error.log
        
        # 新增: 监控 TUN 设备
        [ "${proxy_method}" != "TPROXY" ] && monitor_service &
        
        return 0
      else
        log Error "启动 ${bin_name} 服务失败，请检查 ${run_path}/error_${bin_name}.log 文件。"
        rm -f ${pid_file} >> /dev/null 2>&1
        return 1
      fi
    fi
  else
    log Error "缺少 ${bin_name} 核心，请下载并将其放置在 ${box_path}/bin/ 目录中"
    return 2
  fi
}

# 监控服务
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
    if ! ip rule | grep -q "from all iif $phy_if lookup $1"; then
      log Warn "tun 设备已丢失，正在等待恢复。"
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
      log Info "已重新获取 tun 设备，新 ID: $tunid"
      ip_rule add $tunid >> /dev/null 2>&1
    fi
    sleep 3
  done
}

# 停止服务
stop_service() {
  if [ "${proxy_method}" = "APP" ] ; then
    log Info "关闭通过外部应用运行的代理"
    sudo sysctl net.ipv4.ip_forward=0 >/dev/null 2>&1
    iptables -D FORWARD -o tun+ -j ACCEPT
    iptables -D FORWARD -i tun+ -j ACCEPT
    iptables -t nat -D POSTROUTING -o tun+ -j MASQUERADE
    ip rule del from all table main pref 17999 >/dev/null 2>&1
    ip rule del from all iif ${phy_if} table $(cat ${tunid_file}) pref 17998 >/dev/null 2>&1
    rm -f ${tunid_file} >> /dev/null 2>&1
    log Info "APP 代理服务已停止。"
    return 0
  fi
  if display_bin_status ; then
    log Warn "正在停止 ${bin_name} 服务。"
    kill $(cat ${pid_file}) || killall ${bin_name}
    forward -D >> /dev/null 2>&1
    sleep 1
    display_bin_status
  fi
  rm -f ${pid_file} >> /dev/null 2>&1

  # 新增：停止服务后清理 iptables 规则
  tproxy_control disable >> ${run_path}/run.log 2>> ${run_path}/run_error.log
}
# box.tproxy 功能
tproxy_control() {
  id="222"
  case "$1" in
    enable)
      # 在启用之前清理旧的规则
      iptables="iptables -w 100" && stop_tproxy >> /dev/null 2>&1
      iptables="ip6tables -w 100" && stop_tproxy >> /dev/null 2>&1
      iptables="iptables -w 100" && stop_redirect >> /dev/null 2>&1
      sleep 1
      if ! probe_user_group ; then
        log Error "无法检查 Box 用户组，请确保 ${bin_name} 核心已启动。"
        return 1
      fi
      find_packages_uid
      intranet[${#intranet[@]}]=$(ip address | grep -w inet | grep -v 127 | awk '{print $2}')
      if [ "${proxy_method}" = "TPROXY" ] ; then
        if (zcat /proc/config.gz | grep -q TPROXY) ; then
          log Info "使用 TPROXY: TCP+UDP。"
          log Info "创建 ip(6)tables 透明代理规则。"
          iptables="iptables -w 100"
          start_tproxy && log Info "创建 iptables 透明代理规则完成。" || (log Error "创建 iptables 透明代理规则失败。" && stop_tproxy >> /dev/null 2>&1)
          if [ "${ipv6}" = "enable" ] ; then
            log Info "使用 IPv6。"
            enable_ipv6
            iptables="ip6tables -w 100"
            intranet6[${#intranet6[@]}]=$(ip address | grep -w inet6 | grep -v ::1 | grep -v fe80 | awk '{print $2}')
            start_tproxy && log Info "创建 ip6tables 透明代理规则完成。" || (log Error "创建 ip6tables 透明代理规则失败。" && stop_tproxy >> /dev/null 2>&1)
          else
            disable_ipv6
            log Warn "禁用 IPv6。"
          fi
          # 优化网络设置
          optimize_network
        else
          log Warn "设备不支持 TPROXY，请切换 proxy_method。"
          log Info "使用 REDIRECT: TCP。"
          log Info "创建 iptables 透明代理规则。"
          iptables="iptables -w 100"
          start_redirect && log Info "创建 iptables 透明代理规则完成。" || (log Error "创建 iptables 透明代理规则失败。" && stop_redirect >> /dev/null 2>&1)
          [ "${ipv6}" = "enable" ] && enable_ipv6 && log Info "启用 IPv6。" || (disable_ipv6 && log Warn "禁用 IPv6。")
        fi
      elif [ "${proxy_method}" = "MIXED" ] ; then
        log Info "使用 MIXED: REDIRECT TCP + TUN UDP。"
        log Info "创建 iptables 透明代理规则。"
        iptables="iptables -w 100"
        start_redirect && log Info "创建 iptables 透明代理规则完成。" || (log Error "创建 iptables 透明代理规则失败。" && stop_redirect >> /dev/null 2>&1)
        create_tun_link
        probe_tun_device && forward -I
        [ "${ipv6}" = "enable" ] && enable_ipv6 && log Info "启用 IPv6。" || (disable_ipv6 && log Warn "禁用 IPv6。")
      else
        [ "${proxy_method}" = "REDIRECT" ] && log Info "使用 REDIRECT: TCP。" || log Info "使用 MIXED: TCP+TUN。"
        log Info "创建 iptables 透明代理规则。"
        iptables="iptables -w 100"
        start_redirect && log Info "创建 iptables 透明代理规则完成。" || (log Error "创建 iptables 透明代理规则失败。" && stop_redirect >> /dev/null 2>&1)
        [ "${ipv6}" = "enable" ] && enable_ipv6 && log Info "启用 IPv6。" || (disable_ipv6 && log Warn "禁用 IPv6。")
      fi
      ;;
    disable)
      log Warn "清理 ip(6)tables 透明代理规则。"
      probe_user_group
      iptables="iptables -w 100" && stop_tproxy >> /dev/null 2>&1
      iptables="ip6tables -w 100" && stop_tproxy >> /dev/null 2>&1
      iptables="iptables -w 100" && stop_redirect >> /dev/null 2>&1
      log Warn "清理 ip(6)tables 透明代理规则完成。"
      enable_ipv6
      log Warn "启用 IPv6。"
      return 0
      ;;
    renew)
      log Warn "清理 ip(6)tables 透明代理规则。"
      iptables="iptables -w 100" && stop_tproxy >> /dev/null 2>&1
      iptables="ip6tables -w 100" && stop_tproxy >> /dev/null 2>&1
      iptables="iptables -w 100" && stop_redirect >> /dev/null 2>&1
      log Warn "清理 ip(6)tables 透明代理规则完成。"
      sleep 3
      tproxy_control enable
      ;;
    enable_ipv6)
      enable_ipv6
      log Warn "启用 IPv6。"
      ;;
    disable_ipv6)
      disable_ipv6
      log Warn "禁用 IPv6。"
      ;;
    *)
      log Error "$0 $1 用法: $0 {enable|disable|renew|enable_ipv6|disable_ipv6}"
      ;;
  esac
}

# box.tproxy 辅助函数
uid_list=()
find_packages_uid() {
  for user_package in ${user_packages_list[@]} ; do
    user=$(echo ${user_package} | awk -F ':' '{print $1}')
    package=$(echo ${user_package} | awk -F ':' '{print $2}')
    uid_list[${#uid_list[@]}]=$((${user}*100000+$(cat /data/system/packages.list | grep ${package} | awk '{print $2}')))
  done
}

probe_user_group() {
  if bin_pid=$(busybox pidof ${bin_name}) ; then
    box_user=$(stat -c %U /proc/${bin_pid})
    box_group=$(stat -c %G /proc/${bin_pid})
    return 0
  else
    box_user=$(echo ${box_user_group} | awk -F ':' '{print $1}')
    box_group=$(echo ${box_user_group} | awk -F ':' '{print $2}')
    return 1
  fi
}

start_redirect() {
  # 省略了具体实现，需要将 box.tproxy 中的 start_redirect 函数代码完整粘贴到这里
  # 以下是 start_redirect 函数的完整代码：

  ${iptables} -t nat -N BOX_EXTERNAL
  ${iptables} -t nat -F BOX_EXTERNAL
  ${iptables} -t nat -N BOX_LOCAL
  ${iptables} -t nat -F BOX_LOCAL

  if [ "${bin_name}" = "clash" ] ; then
    ${iptables} -t nat -A BOX_EXTERNAL -p udp --dport 53 -j REDIRECT --to-ports ${clash_dns_port}
    ${iptables} -t nat -A BOX_LOCAL -p udp --dport 53 -j REDIRECT --to-ports ${clash_dns_port}
    ${iptables} -t nat -A BOX_EXTERNAL -d ${clash_fake_ip_range} -p icmp -j DNAT --to-destination 127.0.0.1
    ${iptables} -t nat -A BOX_LOCAL -d ${clash_fake_ip_range} -p icmp -j DNAT --to-destination 127.0.0.1
  #  else
  #    其他类型的入站应在此处添加以接收 DNS 流量而不是嗅探
  #    ${iptables} -t nat -A BOX_EXTERNAL -p udp --dport 53 -j REDIRECT --to-ports ${redir_port}
  #    ${iptables} -t nat -A BOX_LOCAL -p udp --dport 53 -j REDIRECT --to-ports ${redir_port}
  fi

  for subnet in ${intranet[@]} ; do
    ${iptables} -t nat -A BOX_EXTERNAL -d ${subnet} -j RETURN
    ${iptables} -t nat -A BOX_LOCAL -d ${subnet} -j RETURN
  done

  ${iptables} -t nat -A BOX_EXTERNAL -p tcp -i lo -j REDIRECT --to-ports ${redir_port}

  if [ "${ap_list}" != "" ] ; then
    for ap in ${ap_list[@]} ; do
      ${iptables} -t nat -A BOX_EXTERNAL -p tcp -i ${ap} -j REDIRECT --to-ports ${redir_port}
    done
    log Info "${ap_list[*]} 透明代理。"
  fi

  ${iptables} -t nat -I PREROUTING -j BOX_EXTERNAL

  ${iptables} -t nat -I BOX_LOCAL -m owner --uid-owner ${box_user} --gid-owner ${box_group} -j RETURN

  if [ "${ignore_out_list}" != "" ] ; then
    for ignore in ${ignore_out_list[@]} ; do
      ${iptables} -t nat -I BOX_LOCAL -o ${ignore} -j RETURN
    done
    log Info "${ignore_out_list[*]} 忽略透明代理。"
  fi

  if [ "${proxy_mode}" = "blacklist" ] ; then
    if [ "${uid_list}" = "" ] ; then
      # 路由所有
      ${iptables} -t nat -A BOX_LOCAL -p tcp -j REDIRECT --to-ports ${redir_port}
      log Info "所有应用透明代理。"
    else
      # 绕过应用
      for appid in ${uid_list[@]} ; do
        ${iptables} -t nat -I BOX_LOCAL -m owner --uid-owner ${appid} -j RETURN
      done
      # 允许指定应用
      ${iptables} -t nat -A BOX_LOCAL -p tcp -j REDIRECT --to-ports ${redir_port}
      log Info "代理模式: ${proxy_mode}, ${user_packages_list[*]} 不透明代理。"
    fi
  elif [ "${proxy_mode}" = "whitelist" ] ; then
    # 将应用路由到 Box
    for appid in ${uid_list[@]} ; do
      ${iptables} -t nat -A BOX_LOCAL -p tcp -m owner --uid-owner ${appid} -j REDIRECT --to-ports ${redir_port}
    done
    ${iptables} -t nat -A BOX_LOCAL -p tcp -m owner --uid-owner 0 -j REDIRECT --to-ports ${redir_port}
    ${iptables} -t nat -A BOX_LOCAL -p tcp -m owner --uid-owner 1052 -j REDIRECT --to-ports ${redir_port}
    log Info "代理模式: ${proxy_mode}, ${user_packages_list[*]} 透明代理。"
  else
    log Warn "代理模式: ${proxy_mode} 错误。"
    # 路由所有
    ${iptables} -t nat -A BOX_LOCAL -p tcp -j REDIRECT --to-ports ${redir_port}
    log Info "所有应用透明代理。"
  fi

  ${iptables} -t nat -I OUTPUT -j BOX_LOCAL

  ${iptables} -A OUTPUT -d 127.0.0.1 -p tcp -m owner --uid-owner ${box_user} --gid-owner ${box_group} -m tcp --dport ${redir_port} -j REJECT
}

stop_redirect() {
  ${iptables} -t nat -D PREROUTING -j BOX_EXTERNAL

  ${iptables} -t nat -D OUTPUT -j BOX_LOCAL

  ${iptables} -D OUTPUT -d 127.0.0.1 -p tcp -m owner --uid-owner ${box_user} --gid-owner ${box_group} -m tcp --dport ${redir_port} -j REJECT
  ${iptables} -D OUTPUT -d 127.0.0.1 -p tcp -m owner --uid-owner 0 --gid-owner 3005 -m tcp --dport ${redir_port} -j REJECT

  ${iptables} -t nat -F BOX_EXTERNAL
  ${iptables} -t nat -X BOX_EXTERNAL
  ${iptables} -t nat -F BOX_LOCAL
  ${iptables} -t nat -X BOX_LOCAL
}
start_tproxy() {
  if [ "${iptables}" = "ip6tables -w 100" ] ; then
    ip -6 rule add fwmark ${id} table ${id} pref ${id}
    ip -6 route add local default dev lo table ${id}
    ip -6 route add default dev ${tun_device} table ${id}
  else
    ip rule add fwmark ${id} table ${id} pref ${id}
    ip route add local default dev lo table ${id}
    ip route add default dev ${tun_device} table ${id}
  fi

  ${iptables} -t mangle -N BOX_EXTERNAL
  ${iptables} -t mangle -F BOX_EXTERNAL

  # 新增：对 FakeIP 地址范围的流量进行标记和 TPROXY 转发
  if [ "${bin_name}" = "clash" ]; then
    ${iptables} -t mangle -A BOX_EXTERNAL -d ${clash_fake_ip_range} -p tcp -j TPROXY --on-port ${tproxy_port} --tproxy-mark ${id}
  fi

  if [ "${bin_name}" = "clash" ] ; then
    if [ "${iptables}" = "ip6tables -w 100" ] ; then
      ${iptables} -t mangle -A BOX_EXTERNAL -p udp --dport 53 -j RETURN
      for subnet6 in ${intranet6[@]}; do
        ${iptables} -t mangle -A BOX_EXTERNAL -d ${subnet6} -j RETURN
      done
    else
      ${iptables} -t mangle -A BOX_EXTERNAL -p udp --dport 53 -j RETURN
      for subnet in ${intranet[@]} ; do
        ${iptables} -t mangle -A BOX_EXTERNAL -d ${subnet} -j RETURN
      done
    fi
  else
    if [ "${iptables}" = "ip6tables -w 100" ] ; then
      for subnet6 in ${intranet6[@]} ; do
        ${iptables} -t mangle -A BOX_EXTERNAL -d ${subnet6} -p udp ! --dport 53 -j RETURN
        ${iptables} -t mangle -A BOX_EXTERNAL -d ${subnet6} ! -p udp -j RETURN
      done
    else
      for subnet in ${intranet[@]} ; do
        ${iptables} -t mangle -A BOX_EXTERNAL -d ${subnet} -p udp ! --dport 53 -j RETURN
        ${iptables} -t mangle -A BOX_EXTERNAL -d ${subnet} ! -p udp -j RETURN
      done
    fi
  fi

  ${iptables} -t mangle -A BOX_EXTERNAL -p tcp -i lo -j TPROXY --on-port ${tproxy_port} --tproxy-mark ${id}
  ${iptables} -t mangle -A BOX_EXTERNAL -p udp -i lo -j TPROXY --on-port ${tproxy_port} --tproxy-mark ${id}
  if [ "${ap_list}" != "" ] ; then
    for ap in ${ap_list[@]} ; do
      ${iptables} -t mangle -A BOX_EXTERNAL -p tcp -i ${ap} -j TPROXY --on-port ${tproxy_port} --tproxy-mark ${id}
      ${iptables} -t mangle -A BOX_EXTERNAL -p udp -i ${ap} -j TPROXY --on-port ${tproxy_port} --tproxy-mark ${id}
      
    done
    log Info "${ap_list[*]} 透明代理。"
  fi

  ${iptables} -t mangle -I PREROUTING -j BOX_EXTERNAL

  ${iptables} -t mangle -N BOX_LOCAL
  ${iptables} -t mangle -F BOX_LOCAL

  if [ "${ignore_out_list}" != "" ] ; then
    for ignore in ${ignore_out_list[@]} ; do
      ${iptables} -t mangle -I BOX_LOCAL -o ${ignore} -j RETURN
    done
    log Info "${ignore_out_list[*]} 忽略透明代理。"
  fi

  if [ "${bin_name}" = "clash" ] ; then
    if [ "${iptables}" = "ip6tables -w 100" ] ; then
      ${iptables} -t mangle -A BOX_LOCAL -p udp --dport 53 -j RETURN
      for subnet6 in ${intranet6[@]} ; do
        ${iptables} -t mangle -A BOX_LOCAL -d ${subnet6} -j RETURN
      done
    else
      ${iptables} -t mangle -A BOX_LOCAL -p udp --dport 53 -j RETURN
      for subnet in ${intranet[@]} ; do
        ${iptables} -t mangle -A BOX_LOCAL -d ${subnet} -j RETURN
      done
    fi
  else
    if [ "${iptables}" = "ip6tables -w 100" ] ; then
      for subnet6 in ${intranet6[@]} ; do
        ${iptables} -t mangle -A BOX_LOCAL -d ${subnet6} -p udp ! --dport 53 -j RETURN
        ${iptables} -t mangle -A BOX_LOCAL -d ${subnet6} ! -p udp -j RETURN
      done
    else
      for subnet in ${intranet[@]} ; do
        ${iptables} -t mangle -A BOX_LOCAL -d ${subnet} -p udp ! --dport 53 -j RETURN
        ${iptables} -t mangle -A BOX_LOCAL -d ${subnet} ! -p udp -j RETURN
      done
    fi
  fi

  ${iptables} -t mangle -I BOX_LOCAL -m owner --uid-owner ${box_user} --gid-owner ${box_group} -j RETURN

  if [ "${proxy_mode}" = "blacklist" ] ; then
    if [ "${uid_list}" = "" ] ; then
      ${iptables} -t mangle -A BOX_LOCAL -p tcp -j MARK --set-mark ${id}
      ${iptables} -t mangle -A BOX_LOCAL -p udp -j MARK --set-mark ${id}
      log Info "所有应用透明代理。"
    else
      for appid in ${uid_list[@]} ; do
        ${iptables} -t mangle -I BOX_LOCAL -m owner --uid-owner ${appid} -j RETURN
      done
      ${iptables} -t mangle -A BOX_LOCAL -p tcp -j MARK --set-mark ${id}
      ${iptables} -t mangle -A BOX_LOCAL -p udp -j MARK --set-mark ${id}
      log Info "代理模式: ${proxy_mode}, ${user_packages_list[*]} 不透明代理。"
    fi
  elif [ "${proxy_mode}" = "whitelist" ] ; then
    for appid in ${uid_list[@]} ; do
      ${iptables} -t mangle -A BOX_LOCAL -p tcp -m owner --uid-owner ${appid} -j MARK --set-mark ${id}
      ${iptables} -t mangle -A BOX_LOCAL -p udp -m owner --uid-owner ${appid} -j MARK --set-mark ${id}
    done
    ${iptables} -t mangle -A BOX_LOCAL -p tcp -m owner --uid-owner 0 -j MARK --set-mark ${id}
    ${iptables} -t mangle -A BOX_LOCAL -p udp -m owner --uid-owner 0 -j MARK --set-mark ${id}
    ${iptables} -t mangle -A BOX_LOCAL -p tcp -m owner --uid-owner 1052 -j MARK --set-mark ${id}
    ${iptables} -t mangle -A BOX_LOCAL -p udp -m owner --uid-owner 1052 -j MARK --set-mark ${id}
    [ "${bin_name}" != "clash" ] && ${iptables} -t mangle -A BOX_LOCAL -p udp --dport 53 -j MARK --set-mark ${id}
    log Info "代理模式: ${proxy_mode}, ${user_packages_list[*]} 透明代理。"
  else
    log Warn "代理模式: ${proxy_mode} 错误。"
    ${iptables} -t mangle -A BOX_LOCAL -p tcp -j MARK --set-mark ${id}
    ${iptables} -t mangle -A BOX_LOCAL -p udp -j MARK --set-mark ${id}
    log Info "所有应用透明代理。"
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
    ${iptables} -t nat -N CLASH_DNS_EXTERNAL
    ${iptables} -t nat -F CLASH_DNS_EXTERNAL

    ${iptables} -t nat -A CLASH_DNS_EXTERNAL -p udp --dport 53 -j REDIRECT --to-ports ${clash_dns_port}

    ${iptables} -t nat -I PREROUTING -j CLASH_DNS_EXTERNAL

    ${iptables} -t nat -N CLASH_DNS_LOCAL
    ${iptables} -t nat -F CLASH_DNS_LOCAL

    ${iptables} -t nat -A CLASH_DNS_LOCAL -m owner --uid-owner ${box_user} --gid-owner ${box_group} -j RETURN

    ${iptables} -t nat -A CLASH_DNS_LOCAL -p udp --dport 53 -j REDIRECT --to-ports ${clash_dns_port}

    ${iptables} -t nat -I OUTPUT -j CLASH_DNS_LOCAL

    ${iptables} -t nat -I OUTPUT -d ${clash_fake_ip_range} -p icmp -j DNAT --to-destination 127.0.0.1
    ${iptables} -t nat -I PREROUTING -d ${clash_fake_ip_range} -p icmp -j DNAT --to-destination 127.0.0.1

    # 新增 ICMP DNAT 规则
    ${iptables} -t nat -I OUTPUT -p icmp -j DNAT --to-destination 127.0.0.1
    ${iptables} -t nat -I PREROUTING -p icmp -j DNAT --to-destination 127.0.0.1

    # 为局域网设备添加 ICMP DNAT 规则
    for interface in ${ap_list[@]}; do
      ${iptables} -t nat -I PREROUTING -i ${interface} -d ${clash_fake_ip_range} -p icmp -j DNAT --to-destination 127.0.0.1
    done

    # 为局域网设备添加 DNS 转发规则
    for interface in ${ap_list[@]}; do
      ${iptables} -t nat -A CLASH_DNS_EXTERNAL -i ${interface} -p udp --dport 53 -j REDIRECT --to-ports ${clash_dns_port}
    done

    log Info "已为局域网设备添加 ICMP DNAT 和 DNS 转发规则。"

    # 为局域网设备添加 ICMP DNAT 规则
    for interface in ${ap_list[@]}; do
      ${iptables} -t nat -I PREROUTING -i ${interface} -p icmp -j DNAT --to-destination 127.0.0.1
    done

    # 添加日志
    log Info "为本设备和局域网设备配置了 ICMP DNAT 规则。"
  fi

  # 确保 IPv6 ICMP 也被正确处理（如果启用了 IPv6）
  if [ "${iptables}" = "ip6tables -w 100" ] ; then
    ip6tables -t nat -I OUTPUT -p ipv6-icmp -j DNAT --to-destination ::1
    ip6tables -t nat -I PREROUTING -p ipv6-icmp -j DNAT --to-destination ::1

    for interface in ${ap_list[@]}; do
      ip6tables -t nat -I PREROUTING -i ${interface} -p ipv6-icmp -j DNAT --to-destination ::1
    done

    log Info "为本设备和局域网设备配置了 IPv6 ICMP DNAT 规则。"
  fi

  # 添加防火墙规则以允许 ICMP 流量
  ${iptables} -A INPUT -p icmp -j ACCEPT
  ${iptables} -A OUTPUT -p icmp -j ACCEPT
  ${iptables} -A FORWARD -p icmp -j ACCEPT

  if [ "${iptables}" = "ip6tables -w 100" ] ; then
    ip6tables -A INPUT -p ipv6-icmp -j ACCEPT
    ip6tables -A OUTPUT -p ipv6-icmp -j ACCEPT
    ip6tables -A FORWARD -p ipv6-icmp -j ACCEPT
  fi

  log Info "添加了允许 ICMP 流量的防火墙规则。"
}

stop_tproxy() {
  if [ "${iptables}" = "ip6tables -w 100" ] ; then
    ip -6 rule del fwmark ${id} table ${id}
    ip -6 route flush table ${id}
  else
    ip rule del fwmark ${id} table ${id}
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
    ${iptables} -D OUTPUT -d ::1 -p tcp -m owner --uid-owner ${box_user} --gid-owner ${box_group} -m tcp --dport ${tproxy_port} -j REJECT
    ${iptables} -D OUTPUT -d ::1 -p tcp -m owner --uid-owner 0 --gid-owner 3005 -m tcp --dport ${tproxy_port} -j REJECT
  else
    ${iptables} -D OUTPUT -d 127.0.0.1 -p tcp -m owner --uid-owner ${box_user} --gid-owner ${box_group} -m tcp --dport ${tproxy_port} -j REJECT
    ${iptables} -D OUTPUT -d 127.0.0.1 -p tcp -m owner --uid-owner 0 --gid-owner 3005 -m tcp --dport ${tproxy_port} -j REJECT
  fi

  # Android ip6tables 没有 nat 表
  iptables="iptables -w 100"
  ${iptables} -t nat -D PREROUTING -j CLASH_DNS_EXTERNAL

  ${iptables} -t nat -D OUTPUT -j CLASH_DNS_LOCAL

  ${iptables} -t nat -F CLASH_DNS_EXTERNAL
  ${iptables} -t nat -X CLASH_DNS_EXTERNAL

  ${iptables} -t nat -F CLASH_DNS_LOCAL
  ${iptables} -t nat -X CLASH_DNS_LOCAL

  ${iptables} -t nat -D OUTPUT -d ${clash_fake_ip_range} -p icmp -j DNAT --to-destination 127.0.0.1
  ${iptables} -t nat -D PREROUTING -d ${clash_fake_ip_range} -p icmp -j DNAT --to-destination 127.0.0.1
}

enable_ipv6() {
  echo 1 > /proc/sys/net/ipv6/conf/all/accept_ra
  echo 1 > /proc/sys/net/ipv6/conf/wlan0/accept_ra
  echo 0 > /proc/sys/net/ipv6/conf/all/disable_ipv6
  echo 0 > /proc/sys/net/ipv6/conf/default/disable_ipv6
  echo 0 > /proc/sys/net/ipv6/conf/wlan0/disable_ipv6
}

disable_ipv6() {
  echo 0 > /proc/sys/net/ipv6/conf/all/accept_ra
  echo 0 > /proc/sys/net/ipv6/conf/wlan0/accept_ra
  echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
  echo 1 > /proc/sys/net/ipv6/conf/default/disable_ipv6
  echo 1 > /proc/sys/net/ipv6/conf/wlan0/disable_ipv6
}

# 新增: 定期清理连接跟踪表函数
clean_conntrack() {
  # 获取当前连接数
  current_conns=$(cat /proc/sys/net/netfilter/nf_conntrack_count)
  max_conns=$(cat /proc/sys/net/netfilter/nf_conntrack_max)
  
  # 当连接数超过最大值的80%时清理
  if [ $current_conns -gt $((max_conns * 80 / 100)) ]; then
    log Info "连接数过高 ($current_conns), 开始清理连接跟踪表"
    conntrack -F
  fi
}

# 修改 optimize_network 函数，改进错误处理
optimize_network() {
  # 增加最大打开文件数
  ulimit -n 1000000

  # 优化 TCP 参数
  sudo sysctl -w net.ipv4.tcp_fastopen=3
  sudo sysctl -w net.ipv4.tcp_slow_start_after_idle=0
  sudo sysctl -w net.ipv4.tcp_no_metrics_save=1
  sudo sysctl -w net.ipv4.tcp_fin_timeout=15
  sudo sysctl -w net.ipv4.tcp_max_tw_buckets=5000
  sudo sysctl -w net.ipv4.tcp_syncookies=1
  sudo sysctl -w net.ipv4.tcp_rfc1337=1
  sudo sysctl -w net.ipv4.tcp_ecn=1
  sudo sysctl -w net.mptcp.enabled=1
  sudo sysctl -w net.ipv4.tcp_keepalive_time=600
  sudo sysctl -w net.ipv4.tcp_keepalive_probes=5
  sudo sysctl -w net.ipv4.tcp_keepalive_intvl=15

  # 优化内核参数
  sudo sysctl -w net.core.rmem_max=26214400
  sudo sysctl -w net.core.wmem_max=26214400
  sudo sysctl -w net.core.rmem_default=1048576
  sudo sysctl -w net.core.wmem_default=1048576
  sudo sysctl -w net.core.optmem_max=65536
  sudo sysctl -w net.core.somaxconn=8192
  sudo sysctl -w net.core.netdev_max_backlog=8192

  # 优化 IPv4 参数
  sudo sysctl -w net.ipv4.tcp_rmem='4096 87380 67108864'
  sudo sysctl -w net.ipv4.tcp_wmem='4096 65536 67108864'
  sudo sysctl -w net.ipv4.tcp_mtu_probing=1

  # Clash 特定优化
  sudo sysctl -w net.ipv4.ip_forward=1
  sudo sysctl -w net.ipv4.tcp_max_syn_backlog=8192
  sudo sysctl -w net.ipv4.tcp_synack_retries=2
  sudo sysctl -w net.ipv4.tcp_syn_retries=2

  # 优化网络接口队列长度
  for i in $(ls /sys/class/net); do
    [ -e /sys/class/net/$i/tx_queue_len ] && echo 10000 > /sys/class/net/$i/tx_queue_len
  done

  # 增加新的优化功能，带错误处理
  detect_network_interfaces
  
  # 尝试设置 QoS，但不中断执行
  setup_qos || log Warn "QoS 设置失败，继续执行其他优化"
  
  # 尝试设置 ipset，但不中断执行
  setup_ipset || log Warn "ipset 设置失败，继续执行其他优化"
  
  # 设置连接跟踪参数，使用 2>/dev/null 忽略错误输出
  sysctl -w net.netfilter.nf_conntrack_max=131072 2>/dev/null
  sysctl -w net.netfilter.nf_conntrack_tcp_timeout_established=7200 2>/dev/null
  sysctl -w net.netfilter.nf_conntrack_udp_timeout=60 2>/dev/null
  
  # 尝试启用 BBR，但不影响主要功能
  if grep -q "tcp_bbr" "/proc/modules" 2>/dev/null; then
    sysctl -w net.core.default_qdisc=fq 2>/dev/null
    sysctl -w net.ipv4.tcp_congestion_control=bbr 2>/dev/null
    log Info "BBR 已启用"
  else
    log Warn "BBR 不可用，使用默认拥塞控制"
  fi
  
  # QUIC 所需的基础参数
  sudo sysctl -w net.ipv4.udp_mem='65536 131072 262144' 2>/dev/null
  sudo sysctl -w net.ipv4.udp_rmem_min=16384 2>/dev/null
  sudo sysctl -w net.ipv4.udp_wmem_min=16384 2>/dev/null
  
  # QUIC 特定优化
  sudo sysctl -w net.ipv4.udp_l3mdev_accept=1 2>/dev/null
  sudo sysctl -w net.ipv4.tcp_window_scaling=1 2>/dev/null
  
  # 检查 QUIC 环境变量是否设置
  if [ "$enable_quic" = true ]; then
    export GOMAXPROCS=$(nproc)
    export CLASH_EXPERIMENT_QUIC=true
    log Info "QUIC 支持已启用 (CLASH_EXPERIMENT_QUIC=true)"
    log Info "GOMAXPROCS 设置为: $(nproc)"
  else
    log Warn "QUIC 支持未启用"
  fi

  # 验证 QUIC 配置
  if [ -n "$(sysctl -n net.core.rmem_max 2>/dev/null)" ] && \
     [ -n "$(sysctl -n net.core.wmem_max 2>/dev/null)" ]; then
    log Info "QUIC 网络参数配置成功"
  else
    log Warn "QUIC 网络参数配置可能不完整"
  fi


  # 启用 BBR 拥塞控制算法
  sudo sysctl -w net.core.default_qdisc=fq >/dev/null 2>&1
  sudo sysctl -w net.ipv4.tcp_congestion_control=bbr >/dev/null 2>&1

  log Info "网络优化设置完成，当前模式: $network_mode"
}



# 新增：检测和配置网络接口
detect_network_interfaces() {
  # 获取所有路由信息
  route_info=$(ip route show)

  # 初始化端口列表
  interfaces=()

  # 检查并收集所有 wlan 端口
  for interface in $(echo "$route_info" | grep "dev wlan" | awk '{print $3}'); do
    interfaces+=("$interface")
  done

  # 检查并收集所有 rmnet 端口
  for interface in $(echo "$route_info" | grep "dev rmnet" | awk '{print $3}'); do
    interfaces+=("$interface")
  done

  # 检查并收集所有 eth 端口
  for interface in $(echo "$route_info" | grep "dev eth" | awk '{print $3}'); do
    interfaces+=("$interface")
  done

  log Info "检测到的活动网络接口: ${interfaces[*]}"
}

setup_qos() {
  # 检查 tc 命令是否可用
  if ! command -v tc >/dev/null 2>&1; then
    log Warn "tc 命令不可用，跳过 QoS 设置"
    return 1
  fi

  for interface in "${interfaces[@]}"; do
    # 设置 MTU
    if ! ip link set dev "$interface" mtu 10000 2>/dev/null; then
      log Warn "无法设置 $interface 的 MTU，跳过该接口的 MTU 设置"
      continue
    fi

    # 清理现有 QoS 规则
    tc qdisc del dev "$interface" root 2>/dev/null

    # 添加新的 QoS 规则，带错误检查
    if ! tc qdisc add dev "$interface" root handle 1: htb default 10 2>/dev/null; then
      log Warn "无法添加 $interface 的 QoS 根规则，跳过该接口的 QoS 设置"
      continue
    fi

    if ! tc class add dev "$interface" parent 1: classid 1:1 htb rate 1gbit burst 15k 2>/dev/null; then
      log Warn "无法添加 $interface 的 QoS 基础类，跳过该接口的剩余 QoS 设置"
      continue
    fi

    # 添加优先级类，忽略错误
    tc class add dev "$interface" parent 1:1 classid 1:10 htb rate 500mbit ceil 1gbit burst 15k prio 1 2>/dev/null
    tc class add dev "$interface" parent 1:1 classid 1:20 htb rate 300mbit ceil 500mbit burst 15k prio 2 2>/dev/null
    tc class add dev "$interface" parent 1:1 classid 1:30 htb rate 200mbit ceil 300mbit burst 15k prio 3 2>/dev/null

    log Info "$interface 的 QoS 设置完成"
  done
}


setup_ipset() {
  # 检查 ipset 命令是否可用
  if ! command -v ipset >/dev/null 2>&1; then
    log Warn "ipset 命令不可用，跳过 ipset 规则设置"
    return 1
  fi

  # 尝试删除已存在的 ipset
  ipset destroy "$ipset_rules" 2>/dev/null

  # 创建新的 ipset
  if ! ipset create "$ipset_rules" hash:net family inet hashsize 1024 maxelem 65536 2>/dev/null; then
    log Warn "无法创建 ipset，跳过 ipset 规则设置"
    return 1
  fi

  # 添加规则，忽略错误
  for subnet in "${intranet[@]}"; do
    ipset add "$ipset_rules" "$subnet" 2>/dev/null
  done

  log Info "ipset 规则设置完成"
  return 0
}



# 等待用户登录
wait_until_login

# 开始服务
rm "${pid_file}" >> /dev/null 2>&1
mkdir -p "${run_path}"

if [ ! -f "${box_path}/manual" ]; then
  mv "${run_path}/run.log" "${run_path}/run.log.bak" 2>/dev/null
  mv "${run_path}/run_error.log" "${run_path}/run_error.log.bak" 2>/dev/null

  start_service >> "${run_path}/run.log" 2>> "${run_path}/run_error.log"
fi

# 处理命令行参数
case "$1" in
  start)
    display_bin_status || start_service
    ;;
  stop)
    stop_service
    ;;
  restart)
    stop_service
    sleep 2
    start_service
    ;;
  status)
    display_bin_status
    ;;
  *)
    log Error "$0 $1 用法: $0 {start|stop|restart|status}"
    ;;
esac

# 应用网络优化设置
optimize_network

# 在主程序中添加定期清理
(while true; do sleep 3600; clean_conntrack; done) &