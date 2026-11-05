#!/bin/sh
# Tower Web 容器启动脚本。
#
# 只处理 TOWER_DATA_DIR（默认 /app/data）：
# - 以 root 启动时，先把该目录（以及其中已有的 workspace.json 等文件）的属主
#   修正为 node，再用 su-exec 降权执行 CMD；数据库目录由宿主机 root 创建、
#   容器内 node 写不进去，是这个项目最常见的部署事故。
# - 以非 root 启动（镜像默认 USER node，或用户显式 user:）时不尝试 chown：
#   只打印一条可操作的告警并继续启动，由 /api/health 的可写探测把容器标记为
#   unhealthy，而不是静默地让工作区一直为空。
#
# 幂等：每次启动都跑一遍也安全；chown -R 只动元数据，且只作用于数据目录，
# 不会碰 /app 下的镜像文件。目录本来正确时 chown 没有实际效果。
# 只读根文件系统 / read_only: true 下 chown 会失败，脚本降级为告警后继续。
set -eu

DATA_DIR="${TOWER_DATA_DIR:-/app/data}"

fix_ownership() {
  if ! mkdir -p "$DATA_DIR" 2>/dev/null; then
    echo "[tower] 警告：无法创建数据目录 $DATA_DIR（只读文件系统？）。继续启动，健康检查会标记为 unhealthy。" >&2
    return 0
  fi
  if chown -R node:node "$DATA_DIR" 2>/dev/null; then
    echo "[tower] 数据目录属主已确认为 node：$DATA_DIR"
  else
    echo "[tower] 警告：无法把 $DATA_DIR 的属主改为 node（只读文件系统或缺少权限）。继续启动，健康检查会标记为 unhealthy。" >&2
  fi
  return 0
}

if [ "$(id -u)" = "0" ]; then
  fix_ownership
  if command -v su-exec >/dev/null 2>&1; then
    exec su-exec node "$@"
  fi
  echo "[tower] 警告：镜像内缺少 su-exec，无法降权，将以 root 运行服务端。" >&2
  exec "$@"
fi

# 非 root 时不尝试 chown（必然失败）。目录本来就可写就安静启动，
# 只有真的不可写才提示，避免健康部署每次重启都刷一条无关告警。
if [ -d "$DATA_DIR" ] && [ -w "$DATA_DIR" ]; then
  exec "$@"
fi

echo "[tower] 以非 root 用户启动（uid=$(id -u)），且数据目录不可写：$DATA_DIR" >&2
echo "[tower] 容器会被标记为 unhealthy（docker ps 可见），工作区改动会全部失败。修复任选其一：" >&2
echo "[tower]   sudo chown -R 1000:1000 <挂载目录> && docker compose restart tower-web" >&2
echo "[tower]   或在 compose 里加 user: root，让本脚本 chown 后自动降权到 node。" >&2
exec "$@"
