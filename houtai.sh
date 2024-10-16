#!/system/bin/sh

# 定义日志目录和日志文件路径
CLASH_LOG_DIR="/data/adb/box_bll/clash"
MIHOMO_LOG_DIR="/data/adb/box/mihomo"
LOG_FILE="/data/adb/box_bll/run/error_sing-box.log"
MAX_SIZE=$((3 * 1024 * 1024)) # 3MB in bytes

# 清理 clash 日志文件
if [ -d "$CLASH_LOG_DIR" ]; then
    # 删除匹配 clash_*.log 的文件
    rm -f "$CLASH_LOG_DIR"/clash_*.log
    if [ $? -eq 0 ]; then
        echo "已清理 Clash 日志文件位于 $CLASH_LOG_DIR"
    else
        echo "清理 Clash 日志文件失败，请检查权限或路径是否正确。"
    fi
else
    echo "目录 $CLASH_LOG_DIR 不存在。"
fi

# 清理 mihomo 日志文件
if [ -d "$MIHOMO_LOG_DIR" ]; then
    # 删除匹配 mihomo_*.log 的文件
    rm -f "$MIHOMO_LOG_DIR"/mihomo_*.log
    if [ $? -eq 0 ]; then
        echo "已清理 Mihomo 日志文件位于 $MIHOMO_LOG_DIR"
    else
        echo "清理 Mihomo 日志文件失败，请检查权限或路径是否正确。"
    fi
else
    echo "目录 $MIHOMO_LOG_DIR 不存在。"
fi

# 检查 error_sing-box.log 文件是否存在
if [ -f "$LOG_FILE" ]; then
    # 获取日志文件大小
    FILE_SIZE=$(stat -c%s "$LOG_FILE")
    
    # 如果文件大小超过最大限制
    if [ "$FILE_SIZE" -gt "$MAX_SIZE" ]; then
        # 计算需要保留的字节数
        BYTES_TO_KEEP=$MAX_SIZE
        
        # 使用 tail 命令截取最新的日志
        tail -c "$BYTES_TO_KEEP" "$LOG_FILE" > "$LOG_FILE.tmp" && mv "$LOG_FILE.tmp" "$LOG_FILE"
        
        if [ $? -eq 0 ]; then
            echo "日志文件 $LOG_FILE 已截断至最新的 $MAX_SIZE 字节。"
        else
            echo "截断日志文件 $LOG_FILE 失败，请检查权限或路径是否正确。"
        fi
    else
        echo "日志文件 $LOG_FILE 大小未超过 $MAX_SIZE 字节，无需截断。"
    fi
else
    echo "日志文件 $LOG_FILE 不存在。"
fi

# 将脚本放入后台运行并降低优先级以节省电量
nohup nice -n 10 sh -c '
while true; do
    # 这里可以添加需要后台执行的代码
    # 例如，定期执行日志清理任务
    sleep 3600 # 每小时执行一次
done
' > /dev/null 2>&1 &