# Python 保护与分析恢复

[English](python-protection.md) | 简体中文

新增独立 Windows Python 案例，先实测，再把可用方法总结为 skill。不依赖 Palace，
也不改变已有 C++ 构建。实际效果与成本见 [Python 实测结果](python-results.zh-CN.md)。

## 六种方案

同一自有包包含整数递推算法、类与异常、嵌套导入、两个动态插件和独立 JSON 模型资源。
入口每行接收一条 JSON，返回 `answer` 与 `elapsed_ns`。输入使用 `values`，可选
`seed`、`plugin`；私有计时模式还返回 `answer.transform_ns`。

比较源码、仅保留 pyc、PyInstaller onefile、案例 AES-GCM 内存加载、PyArmor 官方试用、
Nuitka standalone。字节码、压缩打包、认证加密、原生编译分别评价，不能统称为不可破解加密。

## Windows 复现

需要 CPython 3.12 x64，在仓库目录执行，使用仓库外的新私有运行目录：

```powershell
python -m venv F:/tmp/anti-rea-python/env
& F:/tmp/anti-rea-python/env/Scripts/python.exe -m pip install --index-url https://pypi.org/simple --report F:/tmp/anti-rea-python/install-report.json -r cases/python-protection/requirements.txt
& F:/tmp/anti-rea-python/env/Scripts/python.exe tools/validate_python_windows.py --out F:/tmp/anti-rea-python/new-run --llvm-bin F:/Program_Professional/xollvm-windows-llvm23-Release/bin --environment F:/Intel/oneAPI/setvars.bat --jobs 8
```

本次解释器为 CPython 3.12.14。依赖版本固定，pip 报告保留下载来源和分发包哈希。
Intel setvars 初始化 MSVC/SDK 环境，其 `compiler/latest/bin/compiler` 提供
`lld-link`，因为指定 xollvm bin 中没有该文件。本次使用 clang-cl 23.1.2 与 LLD 19.0.0，
这是实测组合，不声称 LLVM 工具同版本。本案例没有启用 xollvm 混淆 pass，构建最多 8 核。

默认 `all` 完成构建、行为验证、受限分析和测量。运行目录保留命令日志、源码快照哈希、
逐文件发布包哈希、报告和私有用例。可用 `--phase` 单独诊断；构建和行为验证要求相应输出全新。
对同一发布包修订分析时，用 `--phase analyze --analysis-label analysis-r2` 保留新证据版本。

自动流程不会虚构已恢复算法。审查发布字节码后独立编写候选实现，私有 manifest 记录证据哈希，
再以 `--phase recover --recovery-manifest <文件>` 核对保留的私有用例。
manifest 中的命令是受信代码输入，不是沙箱。调用原保护函数回放不算独立重写。

## 验证边界

每种方案的分析上限为 15 分钟，构建时间另计。静态扫描不执行目标。
已审查自有案例的动态观察显式使用 `--execute`，由外层设置期限并终止超时进程树。
代码对象序列化是实验功能；PyArmor 上已有崩溃记录，后续只观察元数据。
标准库解析器不是系统安全沙箱，未知输入仍需要合适的隔离措施。

分析者知道案例设计。恢复命令只读取发布包和分析结果，排除原始源码、构建输出和私有密钥文件，
但这不属于独立盲测。冻结候选后，才与 256 组固定种子随机输入及 9 组边界/错误输入比较。

AES 案例故意随运行材料携带密钥。它在加载前认证，错误密钥、头部/tag 篡改和截断均被拒绝；
密钥和明文仍可恢复。认证拒绝不代表密钥保密，固定案例加载器也不代表任意项目导入兼容。

私有运行目录包含密钥、解密源码、代码捕获和原始报告，禁止公开或混入发布包。
离线 HTML 提供文件筛选、搜索、偏移/行号或代码对象上下文、baseline 对比和缺项。
本轮浏览器策略阻止本地文件预览，已测试转义和报告隔离，但尚未完成截图验收。

## 独立 Skill

- [Python 保护 Skill](python-protection-skill/index.md)：baseline、工具选择、接入和恢复反证，附依赖检查器。
- [Python 检测 Skill](python-audit-skill/index.md)：独立静态扫描、受限归档提取、可信程序运行观察与私有 HTML。
- 下载 [保护 ZIP](downloads/python-code-protection.zip) 和 [检测 ZIP](downloads/python-leakage-audit.zip)，仅包含审阅过的公开文件。

Skill 指令和参考文档保持英文。保护 ZIP 提供接入指导，不附案例打包器，也不是通用 Python 重写器。
检测 ZIP 的静态命令不依赖 REA、编译器或额外 Python 包；原生分析可选用已有 REA 后端。
