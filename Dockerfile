# syntax=docker/dockerfile:1

# 构建阶段：安装依赖并产出 dist/。运行阶段不需要 node_modules，
# 服务端只使用 Node 内置模块和 server/ 下的本地 .mjs 文件。
# 构建产物是平台无关的 JS/CSS；让构建阶段跑在原生 BUILDPLATFORM，
# 避免 arm64 目标在 QEMU 里执行 npm ci 时崩溃。运行阶段仍使用目标架构。
FROM --platform=$BUILDPLATFORM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json vite.config.ts index.html ./
COPY src ./src
COPY public ./public
RUN npm run build

FROM node:22-alpine AS runtime
ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=8787 \
    TOWER_DATA_DIR=/app/data \
    TOWER_CONTAINER=1
WORKDIR /app
# 测速的 ICMP 模式调用系统 ping；不可用时服务端会自动回退 TCP。
# su-exec 供 entrypoint 在以 root 启动时把服务端降权到 node（amd64 / arm64
# 的 Alpine 都有该包，体积只有几十 KB）。
RUN apk add --no-cache iputils su-exec \
 && mkdir -p /app/data \
 && chown -R node:node /app/data
COPY --chown=node:node --from=build /app/dist ./dist
COPY --chown=node:node server ./server
COPY --chown=node:node public/rulesets ./public/rulesets
COPY --chown=node:node LICENSE THIRD_PARTY_NOTICES.md ./
# 启动脚本：root 启动时自动修正 TOWER_DATA_DIR 属主再降权；非 root 只告警。
COPY --chown=node:node docker/entrypoint.sh ./entrypoint.sh
RUN chmod 0755 /app/entrypoint.sh
# 默认仍以 node 运行（镜像 USER 不变）。绑定了 root 属主的宿主机目录、
# 又希望容器自己修好时，用 `user: root` 启动：entrypoint 会 chown 后降权。
USER node
EXPOSE 8787
# 健康检查同时反映「进程活着」与「数据目录可写」：不可写时 /api/health
# 返回 503，容器在 docker ps 里显示 unhealthy（只警示，不会自动重启）。
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- "http://127.0.0.1:${PORT}/api/health" >/dev/null || exit 1
ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["node", "server/index.mjs"]
