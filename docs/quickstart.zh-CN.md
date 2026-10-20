# 快速开始

[English](quickstart.md) | 简体中文

在仓库根目录运行命令。示例是小型计算引擎，不是可自动改写其他程序的保护 SDK。

## Linux 前置条件

- CMake 3.24+、Ninja、Python 3.10+。
- 保护构建需 Clang 和相同 LLVM 主版本的 `opt`。LLVM 18 可运行基础保护，xollvm 需独立 LLVM 22/23 工具链。
- 编译器旁的 `llvm-cxxfilt` 或 PATH 中的 GNU `c++filt`。
- libsodium 头文件和库，例如 Debian/Ubuntu 的 `libsodium-dev`。

原生 Windows 使用 [clang-cl/JOM 指南](windows.zh-CN.md)。项目不自动下载或替换编译器。

## 准备 Python

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
```

## 构建保护版本

将编译器路径替换为本机工具链：

```bash
cmake --preset protected -DCMAKE_CXX_COMPILER=/path/to/llvm/bin/clang++
cmake --build --preset protected
ctest --test-dir build/protected --output-on-failure
cmake --install build/protected

out/protected/bin/anti-rea-demo selftest
out/protected/bin/anti-rea-demo resource
out/protected/bin/anti-rea-demo warning
```

预设使用 8 个并行任务，默认包含信息保护和安装 ELF 的符号剥离，不启用 xollvm 混淆。私有产物和恢复映射留在 `build/protected`，运行副本安装到 `out/protected`。

!!! note "已有 CMake 缓存"
    修改默认值不会覆盖缓存，请新建构建目录或显式将保护、剥离设为 `ON`。

`warning` 输出密封载荷，可用[离线恢复](diagnostics.zh-CN.md)配合对应密钥和映射解码。`verify`、`assert` 故意 abort，`exception` 故意退出为 3，仅在安全测试环境运行。

## 比较三个版本

```bash
python tools/measure.py --compiler /path/to/llvm/bin/clang++ --jobs 8 --samples 9
```

脚本构建、测试、安装并审计 baseline、stripped、protected，生成 `build/measurement.md`、`.json` 和 `build/measurement-differences.md`、`.json`。能自动找到匹配 Clang/opt 时可省略编译器。统计、仅报告模式和完整矩阵见[测量方法](measurement.zh-CN.md)。

## 使用私有部署密钥

```bash
python tools/anti_rea.py keys --out .private/keys.json
cmake --preset protected -DANTI_REA_KEYS="$PWD/.private/keys.json" \
  -DCMAKE_CXX_COMPILER=/path/to/llvm/bin/clang++
cmake --build --preset protected
ctest --test-dir build/protected --output-on-failure
```

`demo-keys/keys.json` 故意公开，不用于保密部署。真实密钥和对应版本映射须内部归档，不能进入安装包、公开仓库或文档站点。

后续阅读：[泄露场景](scenarios.zh-CN.md)、[构建接入](integration.zh-CN.md)、[xollvm](xollvm.zh-CN.md)、[检测 skill](audit-skill.zh-CN.md)。
