# Storage 受控测试预览 · 静态构建产物

本仓库**只存放构建产物**（由 `scripts/preview-publish.sh` 生成），不存放源码。

## 这不是可用的服务

这里没有控制面：**没有身份认证、没有会话、没有权限、没有审计、没有数据面**。
页面能打开只说明静态字节完整；登录和任何数据操作都需要 Rust 控制面
`preview-server`（见主仓库 `crates/preview`），本仓库无法提供。

真正的受控测试实例运行在受控主机上，需账号登录后访问。

## 内容

| 路径 | 说明 |
|---|---|
| `index.html` `app.js` `style.css` | 工作台 UI |
| `s/` | 存储模块的构建期转译产物（ESM） |
| `wasm/preview-guard.wasm` | 权限内核，与服务端同一份 Rust 源码 |

发布状态：`CONTROLLED_PREVIEW_RELEASED`（静态壳），**不是** `PRODUCTION_RELEASED`。
