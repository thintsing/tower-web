# syntax=docker/dockerfile:1

# 构建阶段：安装依赖并产出 dist/。运行阶段不需要 node_modules，
# 服务端只使用 Node 内置模块和 server/ 下的本地 .mjs 文件。
FROM node:22-alpine AS build
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
RUN apk add --no-cache iputils \
 && mkdir -p /app/data \
 && chown -R node:node /app/data
COPY --chown=node:node --from=build /app/dist ./dist
COPY --chown=node:node server ./server
COPY --chown=node:node public/rulesets ./public/rulesets
COPY --chown=node:node LICENSE THIRD_PARTY_NOTICES.md ./
USER node
EXPOSE 8787
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD-SHELL wget -qO- "http://127.0.0.1:${PORT}/api/health" >/dev/null || exit 1
CMD ["node", "server/index.mjs"]
