# ANTI-REA

[English](README.md) | 简体中文

可复现的 C++ 与 Python 信息泄露实验项目：观察发布程序暴露的信息，实施限定范围的保护，并测量实际变化。

**保护不意味着程序无法被逆向。** 本项目区分诊断保密、不透明 RTTI 名称、发布符号清理和代码混淆四种机制。

## 文档网站

项目使用 MkDocs Material，提供可搜索的技术指南、实测结果和四个可独立下载的 skill。参见[中文文档首页](docs/index.zh-CN.md)和 [GitHub Pages 配置](docs/github-pages.zh-CN.md)。

在线文档：<https://weixuep.github.io/ANTI-REA/index.zh-CN/>

```bash
python -m pip install -r requirements-docs.txt
python -m mkdocs serve
```

推送后在 GitHub 的 **Settings > Pages > Source** 选择 **GitHub Actions**。`Documentation` 工作流验证拉取请求，并部署 `main` 的文档更新。公开基础 URL 从 GitHub 元数据推导，fork 可使用 `ANTI_REA_SITE_URL` 覆盖。

## 可复现实验

- 明文诊断与公钥加密警告，以及离线恢复。
- 普通构建中的源码路径、文件名、条件表达式和函数签名。
- 保留 `dynamic_cast`、`typeid` 和异常行为的 RTTI 名称替换。
- 符号剥离与运行时字符串的差异：仅 strip 无法同时消除两者。
- 可搬迁资源路径、资源别名和私有构建产物隔离。
- xollvm 的轻、中、重及按函数混合 VM 配置。
- 五个策略常量的可选运行时掩码，并分别验证直接字节隐藏与可恢复性。
- 可移植源码/二进制审计工具，以及独立的检测和保护 skill。
- 可选的固定版本 REA 后端，基于原始 baseline 调查原生漏洞候选。
- Windows Python 源码/pyc、PyInstaller、AES 加载、PyArmor 试用和 Nuitka 的[恢复与成本实测](docs/python-results.zh-CN.md)，以及[两个 Python skill](docs/python-protection.zh-CN.md)。

示例是小型通用计算引擎，不是真实求解器。整数工作负载便于精确比较结果，数值热点不参与混淆，无需大型数值依赖。

审计 skill 可独立使用。可选 REA 后端固定在 `third_party/rea`，需要时运行 `git submodule update --init third_party/rea`，再按该版本说明准备依赖和构建。也可选择已有 REA 安装。参见 [REA 接入说明（英文）](skills/cpp-leakage-audit/references/rea.md)，了解 baseline 绑定、只读 CLI、MCP 和证据边界。

## Linux 快速开始

需要 CMake 3.24+、Ninja、Python 3.10+、C++20 编译器和 libsodium 开发文件。保护构建需要 Clang、匹配的 `opt`，以及反修饰工具。LLVM 18 可用于不含 xollvm 的保护；xollvm 需要单独安装 LLVM 22/23 工具链。

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt

cmake --preset baseline -DCMAKE_CXX_COMPILER=/path/to/llvm/bin/clang++
cmake --build --preset baseline
ctest --test-dir build/baseline --output-on-failure

cmake --preset protected -DCMAKE_CXX_COMPILER=/path/to/llvm/bin/clang++
cmake --build --preset protected
ctest --test-dir build/protected --output-on-failure
cmake --install build/protected
```

Debian/Ubuntu 可安装 `libsodium-dev`。配置 CMake 前激活 Python 环境，或设置 `-DPython3_EXECUTABLE=/path/to/.venv/bin/python`。

```bash
build/baseline/bin/anti-rea-demo warning
build/protected/bin/anti-rea-demo warning
build/protected/bin/anti-rea-demo selftest
out/protected/bin/anti-rea-demo resource
```

`verify` 和 `assert` 会故意终止进程；`exception` 的退出码为 3。其他命令包括 `rtti`、`location`、`startup` 和 `bench`。原生 Windows 请参见 [Windows 指南](docs/windows.zh-CN.md)。

## 开关与比较

```bash
# 切换保护配置时使用独立构建目录。
cmake -S . -B build/custom -DANTI_REA_CODE_PROTECTION=ON \
  -DCMAKE_CXX_COMPILER=/path/to/llvm/bin/clang++

# 完整矩阵；工具不可用的配置会标为 Not run。
python tools/anti_rea.py compare --compiler /path/to/llvm/bin/clang++ --jobs 8

# baseline / stripped / protected 三组比较，默认 8 并行任务。
python tools/measure.py
```

新建自定义配置默认 `ANTI_REA_CODE_PROTECTION=ON`、`ANTI_REA_STRIP_RELEASE=ON`、`ANTI_REA_OBFUSCATION=NONE`。信息保护和发布剥离共同启用，函数混淆和 VM 需单独选择。`baseline`、`stripped` 对照预设显式关闭信息保护。已有 CMake 缓存不会随默认值改变，请新建目录或显式设置开关。

`measure.py` 优先寻找 `build/toolchains/xollvm23`，再检查 PATH 中匹配的 Clang/opt；可用 `--compiler`、`--opt` 指定。它干净构建、测试和审计三个安装版本，生成 `build/measurement*.md`、`.json` 及绝对值/百分比差异。参见[测量说明](docs/measurement.zh-CN.md)。

所有比较预设使用 RelWithDebInfo / O2。安装后的 `stripped`、`protected` ELF 被剥离，原始构建产物保持私有。[实测结果](docs/comparison.zh-CN.md)只陈述已运行的配置。

`ANTI_REA_OBFUSCATION=NONE|LIGHT|MEDIUM|HEAVY|MIXED_VM` 独立选择混淆。启用前阅读 [xollvm 接入](docs/xollvm.zh-CN.md)。本项目不会自动下载或替换编译器。

## 可选名称混淆

`ANTI_REA_NAME_STYLE=OPAQUE|DECOY` 可选择原有策略或常见功能词替代名，处理显式选定的
内部函数及 RTTI 类型。Windows 可另选 `ANTI_REA_RETAIN_DECOY_EXPORTS=ON`，将指定替代名
保留为 EXE 导出；默认 OFF，因为它会额外暴露函数地址。范围、恢复和大模型误判假设的边界见
[名称模式](docs/name-styles.zh-CN.md)。

## 恢复示例警告

警告包含 `Payload: AR1:<key-id>:<base64>`，传入完整 token：

```bash
python tools/anti_rea.py decode --build build/protected --token 'AR1:...:...'
python tools/anti_rea.py decode --build build/protected --rtti '65R...'
```

默认密钥为 **PUBLIC DEMO KEYS - NOT SECRET**，任何人都能解密示例。正式部署必须生成自己的密钥：

```bash
python tools/anti_rea.py keys --out .private/keys.json
cmake --preset protected -DANTI_REA_KEYS="$PWD/.private/keys.json" \
  -DCMAKE_CXX_COMPILER=/path/to/llvm/bin/clang++
```

按发布版本归档密钥及 `build/<preset>/private/`，禁止随程序分发。参见[诊断与恢复](docs/diagnostics.zh-CN.md)。

## 审计自己的项目

```bash
python tools/anti_rea.py audit --source examples \
  --binary out/protected/bin/anti-rea-demo \
  --binary out/protected/bin/libengine.so --out build/audit

python tools/anti_rea.py audit --binary /path/to/program \
  --function SensitiveFunction --variable internal_budget \
  --deny 'Confidential error text' --fail-on-deny --out build/target-audit
```

函数名、变量名搜索默认为空，路径始终扫描。两个 skill 可分别安装：

- [cpp-leakage-audit](skills/cpp-leakage-audit/SKILL.md)：只读检测源码、二进制和发布包，保存 baseline、提出建议；附独立扫描器，不生成密钥或修改目标。
- [cpp-code-protection](skills/cpp-code-protection/SKILL.md)：授权范围内接入保护、管理密钥、离线恢复和测量，提供可选 GUI 设计指导；附独立 Python 工具，不包含扫描器或通用重写器。

将所需目录放入代理的 skill 目录即可。二者均不依赖本项目 Python 包或另一个 skill，本项目不全局安装它们。网站分别提供[检测](docs/audit-skill.zh-CN.md)和[保护](docs/using-protection-skill.zh-CN.md)中文使用指南与下载包。skill 入口及其参考文档保持英文。

授权保护任务默认使用剥离后的信息保护发布版本。诊断、位置和 RTTI 机制按目标适配，额外混淆/VM 按函数价值、频率和性能预算选择；没有测量依据时不处理数值热点。只读审计保持只读，三版本测量配置不等于生产保护策略。

## 阅读索引

| 文档 | 用途 |
| --- | --- |
| [文档首页](docs/index.zh-CN.md) | 网站导航 |
| [快速开始](docs/quickstart.zh-CN.md) | 构建、运行和比较 |
| [威胁模型](docs/threat-model.zh-CN.md) | 保护目标及限制 |
| [泄露场景](docs/scenarios.zh-CN.md) | 复现与缓解 |
| [诊断恢复](docs/diagnostics.zh-CN.md) | 加密、密钥与映射 |
| [构建集成](docs/integration.zh-CN.md) | 流水线与项目适配 |
| [xollvm](docs/xollvm.zh-CN.md) | 工具链、强度、报告与开销 |
| [Windows](docs/windows.zh-CN.md) | clang-cl、JOM、PE/PDB |
| [测量方法](docs/measurement.zh-CN.md) | 比较和解释 |
| [实测结果](docs/comparison.zh-CN.md) | 已脱敏结果 |
| [Windows 验证](docs/windows-validation.zh-CN.md) | 原生 demo 与 REA 静态验证 |
| [剩余暴露](docs/remaining-exposure.zh-CN.md) | 仍可观察的信息 |
| [检测 skill](docs/audit-skill.zh-CN.md) | 只读证据与建议 |
| [保护 skill](docs/using-protection-skill.zh-CN.md) | 接入、密钥和恢复 |
| [GitHub Pages](docs/github-pages.zh-CN.md) | 预览与部署 |

## 目录和许可证

`examples/` 为 C++ 示例，`tools/` 为 Python 入口，`src/anti_rea/` 为实现，`skills/` 为独立 skill。生成头文件、私有 LLVM IR、映射和完整测量保存在被忽略的构建目录。

原创示例采用 MIT。xollvm 是采用 Apache-2.0 WITH LLVM-exception 的外部项目；参见 [NOTICE](NOTICE)。REA 为可选 MIT 子模块；工具链、生产私钥和上游应用源码不随本项目示例发布。
