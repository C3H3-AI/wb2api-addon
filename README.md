# WB2API — Home Assistant Add-on

把 **WorkBuddy / CodeBuddy** 账号变成 OpenAI 兼容 API 的 HA 加载项。

> 上游：[Sliverkiss/workbuddy2api](https://github.com/Sliverkiss/workbuddy2api)（MIT）
> 本仓库**只提供 HA 外壳**（清单 / Dockerfile / 启动脚本 / 管理面板），
> 构建时从上游拉取源码编译 —— **不 vendor 副本**。

## 为什么这样做

上游是高频维护的活跃项目（曾一周 157 个提交）。如果采用「复制式 vendor 同步」
（把上游源码拷进本仓库再手工合并），会产生两个长期负担：

1. 上游每次改动都要三方合并；
2. 本仓库的任何本地修改会形成永久分叉。

本仓库改为**构建时拉取**，于是「跟随上游」退化成改一个变量：

```dockerfile
ARG WB2API_REF=master        # 默认跟 master；出问题 pin 成具体 sha 回滚
```

**上游更新 → CI 重建 → 用户更新，全程无需改本仓库任何代码。**

## 安装

1. 在 HA 中添加本仓库为自定义加载项仓库
2. 安装 **WB2API**（镜像从 `ghcr.io/c3h3-ai/wb2api` 拉取，无需本地编译）
3. 配置：
   - `api_key`：OpenAI API 鉴权（**建议设置**；留空则不校验）
   - `webui_user` / `webui_pass`：面板登录（**建议设置**，见下方安全说明）
   - 其余项一般保持默认
4. 启动 → 打开面板 → 「添加账号」

## 使用

### 添加账号

面板点「添加账号」→ 打开弹出的 WorkBuddy 授权页 → 完成登录 → 回到面板点
「我已完成登录」。凭证会落到 `/data/auths/workbuddy-<uid>.json`。

### 调用 API

模型需带前缀（与上游一致）：

```bash
curl http://<HA>:7863/v1/chat/completions \
  -H "Authorization: Bearer <api_key>" \
  -H "Content-Type: application/json" \
  -d '{"model":"glm-5.2","messages":[{"role":"user","content":"hi"}],"stream":true}'
```

`/v1/models` 列出可用模型。

## ⚠️ 安全说明

**建议在配置里设置 `webui_user` / `webui_pass`。**

未设置时，面板管理接口的访问规则：

| 访问方式 | 未配面板账号 | 已配面板账号 |
|---|---|---|
| HA 侧边栏（ingress） | ✅ 放行 | 需登录 |
| 容器内 / 本机回环 | ✅ 放行 | 需登录 |
| **局域网 IP 直连 7863** | ❌ **拒绝** | 需登录 |

之所以不信任整个内网：ingress 转发（`172.30.x`）与局域网直连（`192.168.x`）
**源 IP 同属内网，仅凭 IP 无法区分**；而 `7863/tcp` 映射到宿主机，
默许内网等于把管理接口暴露给同网段任意设备。

被拦截时，任选其一：配置面板账号密码，或改从 HA 侧边栏进入。

> **`/v1/*` OpenAI API 不受上述限制** —— 它由 `api_key` 独立鉴权
> （面板层与 serverd 层各校验一次），与会话登录无关。

面板自身的实现也按安全实践编写：会话 token 用 `secrets.token_urlsafe`
（不可预测），cookie 比较用 `hmac.compare_digest`（恒定时间），
登录失败有 5 次 / 5 分钟限流。

## 定时任务

上游自带的任务由 `serverd` 按配置的整点触发（北京时间）：

| 任务 | 默认时刻 | 说明 |
|---|---|---|
| 签到 | 09、21 点 | 每日签到 + 余额查询，恢复冷却账号 |
| 活跃上报 | 10 点 | 连登天数等 |
| token 保活 | 22 点 | 刷新 token |
| 开学季 / 夜猫子 / 猫猫旅行 | 12 / 1 / 9、21 点 | 上游活动任务 |

各项均可在配置中单独关闭（`*_enabled`）。

## 与 C3H3-AI/ai-proxy 的关系

两个独立的加载项，可并存：

| | **本加载项（wb2api）** | [ai-proxy](https://github.com/C3H3-AI/ai-proxy) |
|---|---|---|
| 上游 | workbuddy2api | wild-work（vendor 同步） |
| 渠道 | WorkBuddy / CodeBuddy | + **TraeWork、Qoder** |
| 跟随上游 | **自动**（构建时拉取） | 需人工 merge |
| 面板 | 薄壳（登录/账号/积分/签到） | 完整 |

**按需选择**：只要 WorkBuddy/CodeBuddy 用本加载项；还需要 TraeWork/Qoder 用 ai-proxy。

## 开发者

```bash
# 本地构建（需能访问 docker.io）
docker build --build-arg BUILD_ARCH=amd64 --build-arg WB2API_REF=master -t wb2api .

# 指定上游 ref（便于回滚）
docker build --build-arg WB2API_REF=<sha> -t wb2api .
```

### 目录结构

```
config.yaml      HA 加载项清单（options / schema / ingress）
Dockerfile       多阶段：clone 上游 → 编译 6 个二进制 → alpine 运行时
run.sh           options → serverd 的 config.json → 拉起面板
panel.py         管理面板 + /v1/* 反向代理
.github/workflows/build-image.yml   定时重建 + 手动触发 + 推送 GHCR
```

### 面板只依赖稳定接口

`panel.py` 刻意只调用上游的**稳定契约**：

- `GET /status`（JSON，带 api_key）
- `/v1/*`（反向代理）
- CLI：`login url|poll`、`signin <dir>`、`credit`（`WB2A_AUTH_DIR`）

**不碰上游内部实现**，所以上游重构不影响面板 —— 这是本加载项维护成本低的关键。

### 自动跟随上游

`.github/workflows/build-image.yml` 每天 UTC 20:00（**北京时间次日 04:00**）自动：

1. clone 上游最新 `master`
2. **先跑 `go build` / `go vet` / `go test`** —— 上游挂了就不构建
3. 构建 amd64 / aarch64 镜像并推送
4. 校验镜像可达

出了问题的回滚方式：把 `WB2API_REF` pin 成上一个可用的 sha 后手动触发。

## License

本加载项外壳代码遵循上游同款 MIT。上游 `workbuddy2api` 的版权与许可声明见其仓库。
