#!/bin/bash
# 双实例冒烟测试：一台机器模拟两台设备（mDNS 在沙箱里可能不可用，用 LANCLIP_PEERS 直连）
set -u
export PATH=$HOME/workspace/.tooling/go/bin:$PATH
cd "$(dirname "$0")"

BIN=/tmp/lanclip-smoke
go build -o "$BIN" ./cmd/lanclip || exit 1

rm -rf /tmp/lc-a /tmp/lc-b
mkdir -p /tmp/lc-a /tmp/lc-b

echo "== 启动设备 A (47717) 和设备 B (47727) =="
LANCLIP_DIR=/tmp/lc-a LANCLIP_PORT=47717 LANCLIP_API_PORT=47718 LANCLIP_PEERS=127.0.0.1:47727 \
  "$BIN" serve > /tmp/lc-a.log 2>&1 &
PA=$!
LANCLIP_DIR=/tmp/lc-b LANCLIP_PORT=47727 LANCLIP_API_PORT=47728 LANCLIP_PEERS=127.0.0.1:47717 \
  "$BIN" serve > /tmp/lc-b.log 2>&1 &
PB=$!
trap "kill $PA $PB 2>/dev/null" EXIT
sleep 2

echo "== 配对：把 A 的 group.key 拷给 B，重启 B =="
cp /tmp/lc-a/group.key /tmp/lc-b/group.key
kill $PB 2>/dev/null; wait $PB 2>/dev/null
LANCLIP_DIR=/tmp/lc-b LANCLIP_PORT=47727 LANCLIP_API_PORT=47728 LANCLIP_PEERS=127.0.0.1:47717 \
  "$BIN" serve > /tmp/lc-b.log 2>&1 &
PB=$!
trap "kill $PA $PB 2>/dev/null" EXIT
sleep 2

PINA=$(LANCLIP_DIR=/tmp/lc-a "$BIN" pin)
PINB=$(LANCLIP_DIR=/tmp/lc-b "$BIN" pin)
echo "A pin=$PINA  B pin=$PINB"
[ "$PINA" = "$PINB" ] || { echo "FAIL: PIN 不一致"; exit 1; }

echo "== 测试1: A -> B 发送文本 =="
LANCLIP_DIR=/tmp/lc-a LANCLIP_PEERS=127.0.0.1:47727 "$BIN" send-text "你好 lanclip 123" || { echo "FAIL: send-text"; exit 1; }
sleep 1
grep -q "收到文本" /tmp/lc-b.log && echo "PASS: B 收到文本" || { echo "FAIL: B 未收到"; tail -5 /tmp/lc-b.log; exit 1; }

echo "== 测试2: B -> A 发送文件 =="
head -c 300000 /dev/urandom > /tmp/lc-b/payload.bin
LANCLIP_DIR=/tmp/lc-b LANCLIP_PEERS=127.0.0.1:47717 "$BIN" send-file /tmp/lc-b/payload.bin || { echo "FAIL: send-file"; exit 1; }
sleep 1
if [ -f /tmp/lc-a/received/payload.bin ]; then
  cmp -s /tmp/lc-b/payload.bin /tmp/lc-a/received/payload.bin && echo "PASS: 文件一致 (300KB)" || { echo "FAIL: 文件不一致"; exit 1; }
else
  echo "FAIL: A 未收到文件"; ls /tmp/lc-a/received/ 2>/dev/null; tail -5 /tmp/lc-a.log; exit 1
fi

echo "== 测试3: 本机 API /api/shot 推送截图 =="
# 生成一个最小 PNG（1x1 红点），base64 经由 python 构造
PNG_B64=$(python3 -c "
import struct, zlib, base64
def chunk(t, d):
    c = t + d
    return struct.pack('>I', len(d)) + c + struct.pack('>I', zlib.crc32(c) & 0xffffffff)
ihdr = struct.pack('>IIBBBBB', 8, 8, 8, 2, 0, 0, 0)
raw = b''.join(b'\x00' + b'\xff\x00\x00' * 8 for _ in range(8))
png = b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', ihdr) + chunk(b'IDAT', zlib.compress(raw)) + chunk(b'IEND', b'')
print(base64.b64encode(png).decode())
")
curl -s -X POST http://127.0.0.1:47718/api/shot \
  -H 'Content-Type: application/json' \
  -d "{\"png_base64\": \"$PNG_B64\", \"name\": \"shot-test\"}" | tee /tmp/shot-resp.json | grep -qE '"sent":[1-9]' \
  && echo "" || { echo "FAIL: /api/shot"; cat /tmp/shot-resp.json; exit 1; }
sleep 1
grep -q "收到图片" /tmp/lc-b.log && echo "PASS: B 收到截图推送" || { echo "FAIL: B 未收到图片"; tail -5 /tmp/lc-b.log; exit 1; }
ls /tmp/lc-b/received/clipboard-*.png >/dev/null 2>&1 && echo "PASS: 图片已落盘（linux 无剪贴板写入，走 fallback）"

echo "== 测试4: 本机 API /api/peers + /api/send-text =="
curl -s http://127.0.0.1:47718/api/peers | grep -q "47727" && echo "PASS: peers 列出 B"
BEFORE=$(grep -c "收到文本" /tmp/lc-a.log)
curl -s -X POST http://127.0.0.1:47728/api/send-text -H 'Content-Type: application/json' \
  -d '{"text":"api 回射测试"}' | grep -qE '"sent":[1-9]' && echo "PASS: /api/send-text"
sleep 2
AFTER=$(grep -c "收到文本" /tmp/lc-a.log)
[ "$AFTER" -gt "$BEFORE" ] && echo "PASS: A 收到 API 文本" || { echo "FAIL: A 未收到 API 文本"; tail -3 /tmp/lc-a.log; exit 1; }

echo "== 测试5: 未配对设备应被拒绝 =="
rm -rf /tmp/lc-evil && mkdir -p /tmp/lc-evil
LANCLIP_DIR=/tmp/lc-evil LANCLIP_PEERS=127.0.0.1:47717 "$BIN" send-text "evil" 2>&1 | grep -qi "reject\|fail\|error" \
  && echo "PASS: 未配对发送被拒绝" || echo "WARN: 未配对设备未被拒绝（检查日志）"

echo ""
echo "ALL SMOKE TESTS DONE"
