# YunDongIP 0.1.1

YunDongIP 0.1.1 是一个独立开发的新型 Cloudflare Anycast 动态优选与自愈工具。

本项目的核心源码、扫描车道、动态节点流水线、测速调度以及 WebSocket 服务端均由本项目自行实现，发布源码仅使用 Go 标准库完成网络、HTTP、WebSocket 握手与帧处理等基础能力。

## 官方来源与版本验证

官方仓库：`https://github.com/zeruiouo-blip/YunDongIP`

源码与程序内置可见项目标识：`YDI-PROVENANCE-0.1.1-A73D91F4`。官方 Release 会提供 SHA-256 校验值；CI 构建还可使用 GitHub 的签名构建来源证明。

## 0.1.1 修复重点

- Android / 手机浏览器增加完整响应式 UI，功能与桌面端一致。
- Windows / macOS / Linux 浏览器按实际窗口宽高自适应工作区，低分辨率也可滚动访问全部功能。
- 数字身份证首跳改为自动识别当前公网出口地区与运营商，并在识别完成后刷新旧缓存画像；不再使用固定城市。
- 精测榜改为扫描阶段分批预整理、O(1) Trace 回填索引、结束后轻量排序，并采用分批可视加载以降低浏览器卡顿。

## 核心机制

- 每个 IP 扫描阶段固定进行 4 次 TCP 握手。
- 扫描层仅做本轮粗筛；损失率达到 60% 或更高时，本轮不进入候选。
- 默认扫描并发 200，上限 1000。
- 全量模式：每个 IPv4 网段每轮 120 个样本。
- 精简模式：每个 IPv4 网段每轮 18 个样本。
- 轮换模式：2 / 3 / 4 / 5 分片，持续轮换候选样本。
- 合格结果进入实时探测流；扫描过程中不因新结果到达而进行全量排序重排。
- CF Trace 在扫描阶段完成地区 / Colo 分类，并通过独立批次实时补齐结果。
- 扫描期间精测榜不做全榜排序或整表重绘，但已完成 CF Trace 的候选会分批预整理，降低结束瞬间压力。
- 扫描完成或人工停止后，前端等待约 30 秒，只做最终排序；详细列表按批显示，避免一次性生成大量 DOM 卡片。
- 后续动态节点流水线采用持续巡检、竞争、保活、冷却、退役与重新晋级机制。
- 全局下载测速采用独占单车道，确保任一时刻只有一个真实下载测速任务占用测速资源。

## 项目定位

YunDongIP 以持续动态优选、自适应节点竞争和长期自愈为核心设计，面向 Cloudflare Anycast IP 的持续筛选与节点管理。它不是传统的一次性扫描后选出若干 IP 的工具，而是围绕持续探测、竞争、保活、冷却、退役与重新晋级建立完整运行机制。

## 目录

`cmd/yundongip/main.go`：程序核心。

`cmd/yundongip/index.html`：项目 Web 前端。

`docs/BEHAVIOR-BASELINE.md`：冻结行为核对表。

`tools/verify_baseline.py`：发布前自动核验脚本。

## 客户端支持

所有客户端都运行完整 YunDongIP 功能，核心扫描、R2 / R3 / R3.5 / R4、测速、域名自动更新、Web 控制等机制保持一致；不同客户端只负责适配各平台的启动与运行方式，不是功能精简版。

| 平台 | 适合用户 | 启动方式 | 独立运行 |
| --- | --- | --- | --- |
| Windows amd64 / arm64 | 新手与普通用户 | 解压后双击程序 | 是 |
| macOS Universal | Apple Silicon / Intel Mac | 双击 YunDongIP.app | 是 |
| Android arm64 | Android 手机用户 | 安装 APK 后点图标 | 是，不依赖电脑 |
| Linux amd64 / arm64 | 服务器与老司机 | 命令行运行 | 是 |

Android 客户端将完整 Go 后端内置到 APK，在手机本机运行，并使用前台服务维持自动优选任务；WebView 只是本机完整控制台界面，不需要连接电脑上的 YunDongIP。

macOS 客户端为可双击的 `YunDongIP.app`，内置 Intel + Apple Silicon Universal Binary。运行数据保存在 `~/Library/Application Support/YunDongIP`。由于当前公开测试版没有 Apple Developer ID 公证，首次从互联网下载后若被 Gatekeeper 提示，可在 Finder 中右键应用并选择“打开”确认一次。

官方 Release 公开发布客户端与保护增强版源码；保护增强版保留 GPL、版权、PROVENANCE、SECURITY、构建脚本与 GitHub Actions 构建来源信息。纯源码包不作为 0.1.1 公开 Release 附件，由维护者单独归档。

## Windows

Windows 用户直接运行 Release `.exe` 即可，不需要安装 Go。双击程序后，默认仅监听本机 `127.0.0.1:13335`，并自动打开浏览器进入 YunDongIP。

如需在局域网内从其他设备访问，可手动启动：`YunDongIP-0.1.1-Windows-x64-Easy/YunDongIP.exe -host 0.0.0.0`。

开发者从源码构建时才需要安装 Go 1.23 或兼容版本。

## 构建

PowerShell：

`./build.ps1`

Linux/macOS：

`bash ./build.sh`

无图形界面的服务器运行时可使用：`-open-browser=false`。

本项目使用 Go 标准库构建，不需要 Go module proxy，不需要下载额外 Go 模块。

## 许可证

YunDongIP 0.1.1 使用 GNU General Public License v3.0（GPL-3.0-only）发布。详见仓库中的 `LICENSE` 文件。
