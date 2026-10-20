# 在 GitHub Pages 发布文档

[English](github-pages.md) | 简体中文

仓库提供 MkDocs Material 网站及 GitHub Actions 工作流。构建网站无需 C++ 编译器、libsodium 或 xollvm。
仓库：<https://github.com/WEIXUEP/ANTI-REA>；文档：<https://weixuep.github.io/ANTI-REA/>。

## 本地预览

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-docs.txt
python -m mkdocs serve --dev-addr 127.0.0.1:8000
```

打开 `http://127.0.0.1:8000/`，修改文档后会自动重载。正式构建检查：

```bash
python -m unittest discover -s tests -p test_docs.py -v
python -m mkdocs build --strict
```

生成内容在 Git 忽略的 `build/site`。链接和导航警告会使严格构建失败。
无需提交 HTML 或建立提交式 `gh-pages` 分支，部署使用 Actions 产物。

## 首次启用 Pages

1. 将仓库及文档工作流推送到 GitHub。
2. 打开 **Settings > Pages > Build and deployment**。
3. Source 选择 **GitHub Actions**；不可选时请管理员检查可见性、套餐及组织策略。
4. 推送文档修改到 `main`，或在 **Actions** 手动运行 `main` 的 **Documentation** 工作流。
5. 从 `github-pages` 环境或 Pages 设置打开实际部署 URL。

普通项目仓库地址格式为：

```text
https://<owner>.github.io/<repository>/
```

工作流从 GitHub 元数据获取所有者/仓库名，本地默认值指向本仓库。
发布需要真实远端及 Pages 设置，本地检查不证明远端部署完成。
管理员也可用已登录的 GitHub CLI：

```bash
# 尚无 Pages 网站时的一次性初始化。
gh api --method POST repos/OWNER/REPOSITORY/pages -f build_type=workflow

# 检查发布源。
gh api repos/OWNER/REPOSITORY/pages --jq '.build_type'
```

已有网站用 `--method PUT` 修改源，预期 `build_type` 为 `workflow`。
普通 `GITHUB_TOKEN` 可部署已启用的网站，不能首次启用；只加 `configure-pages` 的
`enablement: true` 仍需要额外管理员令牌。优先按上述设置/API 初始化，日常部署无需新增令牌或 secret。

## 部署行为

拉取请求只构建验证，`main` 推送部署；手动部署也要求 `main`。
部署使用 `github-pages` 环境并保留正在执行的部署，不自动取消。
工作流使用 Node.js 24 actions，包括 Pages 上传器内部嵌套的 upload action；
仅升级 checkout/setup-python 无法消除旧 Pages actions 的 Node.js 20 警告。
执行环境为 GitHub 托管 Ubuntu。

路径过滤覆盖文档、skill、site hook、配置和文档测试；仅 C++ 源码变化不重建网站。
自定义域名/URL 时设置仓库 Actions 变量 `ANTI_REA_SITE_URL`，包含结尾 `/`；域名和 DNS 单独配置。
本地生产构建检查 canonical URL 时使用相同环境变量。

## 公开范围

网站包含 `docs/`、审阅过的测量摘要、两个生成的 skill 下载包及项目许可。
site hook 按文件白名单发布，不遍历私有或构建目录。skill Markdown 直接从规范源生成网页，
公开使用指南提供中英文版本，skill 入口及参考文档保持英文，下载包也保留英文版本。

不要在 `docs/` 放原始审计、私有诊断映射、密钥、IR、PDB 或本机发布包。
即使不在导航内，目录中的文件仍可能公开。测量 JSON 发布前也须审阅。

| 问题 | 检查 |
| --- | --- |
| `configure-pages` 报 `HttpError: Not Found` | 首次启用 Pages 并选 Actions，检查管理员及组织策略 |
| Pages 404 | 等待成功部署，核对环境 URL，包含仓库路径 |
| 移动文件后导航断裂 | 执行 `mkdocs build --strict` 并修正 Markdown 目标 |
| canonical URL 异常 | 检查 `ANTI_REA_SITE_URL`，尤其是 fork |
| 本地 skill 改动未出现 | 重建或重启 `mkdocs serve`，skill 位于 `docs/` 外 |
| 部署等待审批 | 检查 `github-pages` 环境保护规则 |
