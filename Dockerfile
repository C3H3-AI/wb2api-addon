# WB2API — Home Assistant Add-on
#
# 设计要点：**不 vendor 上游源码**。
# 构建时从 Sliverkiss/workbuddy2api 拉取指定 ref 再编译，因此：
#   - 上游更新只需重新构建（WB2API_REF 默认 master；出问题可 pin 回某个 sha）
#   - 本仓库不含任何上游 Go 代码 → 不存在「vendor 漂移 / 三方合并」的维护成本
#
# 上游为 MIT License，见 https://github.com/Sliverkiss/workbuddy2api

# ============================================================
# 阶段一：拉取上游并编译
# ============================================================
FROM docker.io/library/golang:1.25-alpine AS build

ARG BUILD_ARCH
ARG BUILD_VERSION
# 要构建的上游 ref：默认 master（准实时跟随）；出问题时 pin 成具体 sha 回滚
ARG WB2API_REF=master

ENV GOPROXY=https://goproxy.cn,direct
RUN sed -i 's|dl-cdn.alpinelinux.org|mirrors.tuna.tsinghua.edu.cn|g' /etc/apk/repositories \
 && apk add --no-cache git

# 拉取上游（只取需要的 ref，浅克隆省时间）
RUN git clone --depth 1 --branch "${WB2API_REF}" \
      https://github.com/Sliverkiss/workbuddy2api /src \
 || (git clone https://github.com/Sliverkiss/workbuddy2api /src \
     && cd /src && git checkout "${WB2API_REF}")

# 记录实际构建的 commit，便于回滚与追溯
RUN cd /src && git rev-parse HEAD > /upstream-commit.txt \
 && echo "==> upstream commit: $(cat /upstream-commit.txt)"

# 编译：注意 GOARCH 映射（HA 的 aarch64 对应 Go 的 arm64）
RUN cd /src && \
    if [ "$BUILD_ARCH" = "aarch64" ]; then export GOARCH=arm64; else export GOARCH=amd64; fi && \
    echo "building GOOS=linux GOARCH=$GOARCH" && \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/serverd  ./cmd/server  && \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/login    ./cmd/login   && \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/signin   ./cmd/signin  && \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/credit   ./cmd/credit  && \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/activity ./cmd/activity && \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/trial    ./cmd/trial

# ============================================================
# 阶段二：运行时
# ============================================================
FROM docker.io/library/alpine:3.20

ARG BUILD_VERSION
ARG BUILD_ARCH

# 时区：容器默认 UTC 会让 scheduler 里 time.Now() 取到 UTC，
# 使 options 配置的 9 点实际在北京时间 17 点触发签到 / 保活。
ENV TZ=Asia/Shanghai

LABEL \
    io.hass.version="${BUILD_VERSION}" \
    io.hass.arch="${BUILD_ARCH}" \
    io.hass.type="addon" \
    io.hass.name="WB2API" \
    io.hass.description="WorkBuddy / CodeBuddy 多账号 OpenAI 兼容代理" \
    io.hass.url="https://github.com/C3H3-AI/wb2api-addon"

RUN sed -i 's|dl-cdn.alpinelinux.org|mirrors.tuna.tsinghua.edu.cn|g' /etc/apk/repositories \
 && apk add --no-cache \
        bash \
        curl \
        jq \
        python3 \
        ca-certificates \
        tzdata \
 && adduser -D -u 10001 app \
 && mkdir -p /app /data/auths /data/data \
 && chown -R app:app /app /data

COPY --from=build /out/serverd  /app/serverd
COPY --from=build /out/login    /app/login
COPY --from=build /out/signin   /app/signin
COPY --from=build /out/credit   /app/credit
COPY --from=build /out/activity /app/activity
COPY --from=build /out/trial    /app/trial
COPY --from=build /upstream-commit.txt /app/upstream-commit.txt

COPY run.sh     /run.sh
COPY panel.py   /app/panel.py
RUN chmod a+x /run.sh /app/serverd /app/login /app/signin /app/credit \
              /app/activity /app/trial /app/panel.py

WORKDIR /app

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD wget -qO- http://127.0.0.1:7863/healthz || exit 1

EXPOSE 7863

CMD [ "/run.sh" ]
