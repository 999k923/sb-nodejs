#!/bin/bash
set -e

# ================== 强制切换到脚本所在目录 ==================
cd "$(dirname "$0")"

# ================== 环境变量 & 绝对路径 ==================
export FILE_PATH="${PWD}/.npm"
export DATA_PATH="${PWD}/singbox_data"
mkdir -p "$FILE_PATH" "$DATA_PATH"

# ================== 获取公网 IP ==================
echo -e "\e[1;36m[网络] 获取公网 IP...\e[0m"
PUBLIC_IP=$(curl -s --max-time 5 ipv4.ip.sb || curl -s --max-time 5 api.ipify.org || curl -s --max-time 5 ifconfig.me || echo "")

if [ -z "$PUBLIC_IP" ]; then
    echo -e "\e[1;31m[错误] 无法获取公网 IP，退出\e[0m"
    exit 1
fi
echo -e "\e[1;32m[网络] 公网 IP: $PUBLIC_IP\e[0m"

# ================== 获取容器分配的端口 ==================
echo -e "\e[1;36m[端口] 检测容器分配的端口...\e[0m"

get_allocated_ports() {
    local ports=()
    
    # 方法1: 从 Pterodactyl 环境变量获取 SERVER_PORT
    if [ -n "$SERVER_PORT" ]; then
        ports+=($SERVER_PORT)
    fi
    
    # 方法2: 遍历所有环境变量查找额外端口
    while IFS='=' read -r name value; do
        # 匹配 ALLOC_PORT_*, P_PORT_*, SERVER_PORT_* 等格式（排除已添加的 SERVER_PORT）
        if [[ "$name" =~ ^(ALLOC_PORT_|P_PORT_|SERVER_PORT_) ]] || \
           [[ "$name" =~ _PORT[0-9]*$ && "$name" != "SERVER_PORT" ]]; then
            if [[ "$value" =~ ^[0-9]+$ ]] && [ "$value" -gt 1024 ] && [ "$value" -lt 65536 ]; then
                # 避免重复
                local exists=0
                for p in "${ports[@]}"; do
                    [ "$p" == "$value" ] && exists=1 && break
                done
                [ $exists -eq 0 ] && ports+=($value)
            fi
        fi
    done < <(env)
    
    # 方法3: 从配置文件读取
    if [ ${#ports[@]} -eq 0 ] && [ -f "${FILE_PATH}/ports.txt" ]; then
        while read -r port; do
            [[ "$port" =~ ^[0-9]+$ ]] && ports+=($port)
        done < "${FILE_PATH}/ports.txt"
    fi
    
    # 只输出纯数字端口，用空格分隔
    echo "${ports[*]}"
}

# 获取端口（捕获纯净输出）
PORTS_STRING=$(get_allocated_ports)
read -ra AVAILABLE_PORTS <<< "$PORTS_STRING"
PORT_COUNT=${#AVAILABLE_PORTS[@]}

# 显示检测到的端口
if [ $PORT_COUNT -gt 0 ]; then
    echo -e "\e[1;32m[端口] 发现 $PORT_COUNT 个可用端口: ${AVAILABLE_PORTS[*]}\e[0m"
else
    echo -e "\e[1;33m[端口] 未自动检测到端口\e[0m"
    echo -e "\e[1;36m当前环境变量（含 PORT）:\e[0m"
    env | grep -i port || echo "  (无)"
    echo ""
    echo -e "\e[1;31m[错误] 未找到可用端口\e[0m"
    echo -e "\e[1;33m请创建文件 ${FILE_PATH}/ports.txt 并写入端口号（每行一个）\e[0m"
    exit 1
fi

# ================== 根据端口数量分配 ==================
# 策略：
# 1个端口：TUIC(UDP) + Reality(TCP) 共用
# 2个端口：TUIC(UDP) + Reality(TCP) 共用一个，HY2(UDP) 单独一个
# 3个及以上：TUIC 一个，HY2 一个，Reality 一个

if [ $PORT_COUNT -eq 1 ]; then
    TUIC_PORT=${AVAILABLE_PORTS[0]}
    HY2_PORT=""
    REALITY_PORT=${AVAILABLE_PORTS[0]}
    echo -e "\e[1;33m[端口分配] 单端口模式（TUIC + Reality 共用）\e[0m"
    echo -e "  TUIC(UDP) + Reality(TCP): $TUIC_PORT"
elif [ $PORT_COUNT -eq 2 ]; then
    TUIC_PORT=${AVAILABLE_PORTS[0]}
    HY2_PORT=${AVAILABLE_PORTS[1]}
    REALITY_PORT=${AVAILABLE_PORTS[0]}
    echo -e "\e[1;33m[端口分配] 双端口模式\e[0m"
    echo -e "  TUIC(UDP) + Reality(TCP): $TUIC_PORT"
    echo -e "  HY2(UDP): $HY2_PORT"
else
    TUIC_PORT=${AVAILABLE_PORTS[0]}
    HY2_PORT=${AVAILABLE_PORTS[1]}
    REALITY_PORT=${AVAILABLE_PORTS[2]}
    echo -e "\e[1;33m[端口分配] 多端口模式\e[0m"
    echo -e "  TUIC(UDP): $TUIC_PORT"
    echo -e "  HY2(UDP): $HY2_PORT"
    echo -e "  Reality(TCP): $REALITY_PORT"
fi

echo ""

# ================== UUID 固定保存 ==================
UUID_FILE="${FILE_PATH}/uuid.txt"
if [ -f "$UUID_FILE" ]; then
  UUID=$(cat "$UUID_FILE")
  echo -e "\e[1;33m[UUID] 复用固定 UUID: $UUID\e[0m"
else
  UUID=$(cat /proc/sys/kernel/random/uuid)
  echo "$UUID" > "$UUID_FILE"
  chmod 600 "$UUID_FILE"
  echo -e "\e[1;32m[UUID] 首次生成并永久保存: $UUID\e[0m"
fi

# ================== 架构检测 & 下载 sing-box ==================
ARCH=$(uname -m)
BASE_URL=""
if [[ "$ARCH" == "arm"* ]] || [[ "$ARCH" == "aarch64" ]]; then
  BASE_URL="https://arm64.ssss.nyc.mn"
elif [[ "$ARCH" == "amd64"* ]] || [[ "$ARCH" == "x86_64" ]]; then
  BASE_URL="https://amd64.ssss.nyc.mn"
elif [[ "$ARCH" == "s390x" ]]; then
  BASE_URL="https://s390x.ssss.nyc.mn"
else
  echo "不支持的架构: $ARCH"
  exit 1
fi

FILE_INFOS=("sb sing-box")
declare -A FILE_MAP

download_file() {
  local URL=$1
  local FILENAME=$2
  if command -v curl >/dev/null 2>&1; then
    curl -L -sS -o "$FILENAME" "$URL" && echo -e "\e[1;32m下载 $FILENAME (curl)\e[0m"
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O "$FILENAME" "$URL" && echo -e "\e[1;32m下载 $FILENAME (wget)\e[0m"
  else
    echo -e "\e[1;31m未找到 curl 或 wget\e[0m"
    exit 1
  fi
}

for entry in "${FILE_INFOS[@]}"; do
  URL=$(echo "$entry" | cut -d ' ' -f1)
  NAME=$(echo "$entry" | cut -d ' ' -f2)
  NEW_NAME="${FILE_PATH}/$(head /dev/urandom | tr -dc a-z0-9 | head -c6)"
  download_file "${BASE_URL}/${URL}" "$NEW_NAME"
  chmod +x "$NEW_NAME"
  FILE_MAP[$NAME]="$NEW_NAME"
done

# ================== 固定 Reality 密钥 ==================
KEY_FILE="${FILE_PATH}/key.txt"
if [ -f "$KEY_FILE" ]; then
  echo -e "\e[1;33m[密钥] 检测到已有密钥，复用...\e[0m"
  private_key=$(grep "PrivateKey:" "$KEY_FILE" | awk '{print $2}')
  public_key=$(grep "PublicKey:" "$KEY_FILE" | awk '{print $2}')
else
  echo -e "\e[1;33m[密钥] 首次生成 Reality 密钥对...\e[0m"
  output=$("${FILE_MAP[sing-box]}" generate reality-keypair)
  echo "$output" > "$KEY_FILE"
  private_key=$(echo "$output" | awk '/PrivateKey:/ {print $2}')
  public_key=$(echo "$output" | awk '/PublicKey:/ {print $2}')
  chmod 600 "$KEY_FILE"
  echo -e "\e[1;32m[密钥] 密钥已保存\e[0m"
fi

# ================== 生成证书 ==================
if ! command -v openssl >/dev/null 2>&1; then
  cat > "${FILE_PATH}/private.key" <<'EOF'
-----BEGIN EC PARAMETERS-----
BggqhkjOPQMBBw==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIM4792SEtPqIt1ywqTd/0bYidBqpYV/+siNnfBYsdUYsoAoGCCqGSM49
AwEHoUQDQgAE1kHafPj07rJG+HboH2ekAI4r+e6TL38GWASAnngZreoQDF16ARa/
TsyLyFoPkhTxSbehH/OBEjHtSZGaDhMqQ==
-----END EC PRIVATE KEY-----
EOF
  cat > "${FILE_PATH}/cert.pem" <<'EOF'
-----BEGIN CERTIFICATE-----
MIIBejCCASGgAwIBAgIUFWeQL3556PNJLp/veCFxGNj9crkwCgYIKoZIzj0EAwIw
EzERMA8GA1UEAwwIYmluZy5jb20wHhcNMjUwMTAxMDEwMTAwWhcNMzUwMTAxMDEw
MTAwWjATMREwDwYDVQQDDAhiaW5nLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEH
A0IABNZB2nz49O6yRvh26B9npACOK/nuky9/BlgEgJ54Ga3qEAxdegEWv07Mi8ha
D5IU8Um3oR/zgRIx7UmRmg4TKkOjUzBRMB0GA1UdDgQWBBTV1cFID7UISE7PLTBR
BfGbgrkMNzAfBgNVHSMEGDAWgBTV1cFID7UISE7PLTBRBfGbgrkMNzAPBgNVHRMB
Af8EBTADAQH/MAoGCCqGSM49BAMCA0cAMEQCIARDAJvg0vd/ytrQVvEcSm6XTlB+
eQ6OFb9LbLYL9Zi+AiB+foMbi4y/0YUQlTtz7as9S8/lciBF5VCUoVIKS+vX2g==
-----END CERTIFICATE-----
EOF
else
  openssl ecparam -genkey -name prime256v1 -out "${FILE_PATH}/private.key" 2>/dev/null
  openssl req -new -x509 -days 3650 -key "${FILE_PATH}/private.key" -out "${FILE_PATH}/cert.pem" -subj "/CN=bing.com" 2>/dev/null
fi
chmod 600 "${FILE_PATH}/private.key"

# ================== 生成 config.json ==================
INBOUNDS=""

# TUIC（UDP协议）
if [ -n "$TUIC_PORT" ]; then
  [ -n "$INBOUNDS" ] && INBOUNDS="${INBOUNDS},"
  INBOUNDS="${INBOUNDS}{
    \"type\": \"tuic\",
    \"listen\": \"::\",
    \"listen_port\": ${TUIC_PORT},
    \"users\": [{\"uuid\": \"${UUID}\", \"password\": \"admin\"}],
    \"congestion_control\": \"bbr\",
    \"tls\": {
      \"enabled\": true,
      \"alpn\": [\"h3\"],
      \"certificate_path\": \"${FILE_PATH}/cert.pem\",
      \"key_path\": \"${FILE_PATH}/private.key\"
    }
  }"
fi

# HY2（UDP协议）
if [ -n "$HY2_PORT" ]; then
  [ -n "$INBOUNDS" ] && INBOUNDS="${INBOUNDS},"
  INBOUNDS="${INBOUNDS}{
    \"type\": \"hysteria2\",
    \"listen\": \"::\",
    \"listen_port\": ${HY2_PORT},
    \"users\": [{\"password\": \"${UUID}\"}],
    \"masquerade\": \"https://bing.com\",
    \"tls\": {
      \"enabled\": true,
      \"alpn\": [\"h3\"],
      \"certificate_path\": \"${FILE_PATH}/cert.pem\",
      \"key_path\": \"${FILE_PATH}/private.key\"
    }
  }"
fi

# Reality（TCP协议）
if [ -n "$REALITY_PORT" ]; then
  [ -n "$INBOUNDS" ] && INBOUNDS="${INBOUNDS},"
  INBOUNDS="${INBOUNDS}{
    \"type\": \"vless\",
    \"listen\": \"::\",
    \"listen_port\": ${REALITY_PORT},
    \"users\": [{\"uuid\": \"${UUID}\", \"flow\": \"xtls-rprx-vision\"}],
    \"tls\": {
      \"enabled\": true,
      \"server_name\": \"www.nazhumi.com\",
      \"reality\": {
        \"enabled\": true,
        \"handshake\": {\"server\": \"www.nazhumi.com\", \"server_port\": 443},
        \"private_key\": \"${private_key}\",
        \"short_id\": [\"\"]
      }
    }
  }"
fi

cat > "${FILE_PATH}/config.json" <<EOF
{
  "log": { "disabled": true },
  "inbounds": [${INBOUNDS}],
  "outbounds": [{"type": "direct"}]
}
EOF

# ================== 启动 sing-box ==================
"${FILE_MAP[sing-box]}" run -c "${FILE_PATH}/config.json" &
SINGBOX_PID=$!
echo -e "\e[1;32m[SING-BOX] 启动完成 PID=$SINGBOX_PID\e[0m"

# ================== 获取 ISP ==================
ISP=$(curl -s --max-time 2 https://speed.cloudflare.com/meta | awk -F'"' '{print $26"-"$18}' 2>/dev/null || echo "Unknown")
echo -e "\e[1;32m[网络] ISP: $ISP\e[0m"

# ================== 生成订阅 ==================
> "${FILE_PATH}/list.txt"

[ -n "$TUIC_PORT" ] && \
  echo "tuic://${UUID}:admin@${PUBLIC_IP}:${TUIC_PORT}?sni=www.bing.com&alpn=h3&congestion_control=bbr&allowInsecure=1#TUIC-${ISP}" >> "${FILE_PATH}/list.txt"

[ -n "$HY2_PORT" ] && \
  echo "hysteria2://${UUID}@${PUBLIC_IP}:${HY2_PORT}/?sni=www.bing.com&insecure=1#Hysteria2-${ISP}" >> "${FILE_PATH}/list.txt"

[ -n "$REALITY_PORT" ] && \
  echo "vless://${UUID}@${PUBLIC_IP}:${REALITY_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.nazhumi.com&fp=firefox&pbk=${public_key}&type=tcp#Reality-${ISP}" >> "${FILE_PATH}/list.txt"

base64 "${FILE_PATH}/list.txt" | tr -d '\n' > "${FILE_PATH}/sub.txt"

echo ""
echo -e "\e[1;35m==================== 节点信息 ====================\e[0m"
cat "${FILE_PATH}/list.txt"
echo -e "\e[1;35m===================================================\e[0m"
echo -e "\e[1;32m订阅文件: ${FILE_PATH}/sub.txt\e[0m"
echo ""

# ================== 定时重启 ==================
schedule_restart() {
  echo -e "\e[1;36m[定时重启] 已启动（北京时间 00:03）\e[0m"
  LAST_RESTART_DAY=-1

  while true; do
    now_ts=$(date +%s)
    beijing_ts=$((now_ts + 28800))
    H=$(( (beijing_ts / 3600) % 24 ))
    M=$(( (beijing_ts / 60) % 60 ))
    D=$(( beijing_ts / 86400 ))

    if [ "$H" -eq 0 ] && [ "$M" -eq 3 ] && [ "$D" -ne "$LAST_RESTART_DAY" ]; then
      echo -e "\e[1;33m[定时重启] 00:03 → 重启 sing-box\e[0m"
      LAST_RESTART_DAY=$D

      kill "$SINGBOX_PID" 2>/dev/null || true
      sleep 3

      "${FILE_MAP[sing-box]}" run -c "${FILE_PATH}/config.json" &
      SINGBOX_PID=$!

      echo -e "\e[1;32m[重启完成] 新 PID: $SINGBOX_PID\e[0m"
    fi

    sleep 30
  done
}

schedule_restart
