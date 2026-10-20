# xollvm 接入与强度等级

[English](xollvm.md) | 简体中文

外部项目：<https://github.com/und3ath/xollvm>。目标版本 **v0.11.1**，commit `eb0850bd7cc87f551ad2948826605e518f5b8aa2`。使用固定版本文档；该版本支持 LLVM 22/23，编译器和 opt 主版本必须一致。

## 自行准备工具链

遵循[固定构建指南](https://github.com/und3ath/xollvm/blob/v0.11.1/docs/BUILD.md)。Linux 可用内置 pass 工具链或匹配 LLVM 的插件。Windows 使用静态扩展工具链，普通预编译 LLVM 未必导出插件所需符号。

项目不下载工具或替换系统编译器，可使用任意本地已解压目录。工具留在版本控制外，如 `build/toolchains/`。

Linux 实测使用操作者提供的 `xollvm-linux-llvm23-Release.tar.zst`，SHA-256 `5766b3a9f1342b5d2040c229dc22e586f3e65eec389fcd41e46d224fd8797a8c`。报告 Clang/LLVM 23.1.2、LLVM commit `ba019b7aafce09a013cf7e9139fa0c229f09b188`；这不能独立证明压缩包的 xollvm 源码版本。已检查可用 pass 和 schema，运行完整强度矩阵。工具解压于 Linux 文件系统，没有使用 Windows 挂载构建目录或替换系统编译器。

```bash
python tools/anti_rea.py doctor \
  --compiler /path/to/xollvm/bin/clang++ \
  --opt /path/to/xollvm/bin/opt --level LIGHT

cmake --preset obfuscated-light \
  -DCMAKE_CXX_COMPILER=/path/to/xollvm/bin/clang++ \
  -DANTI_REA_OPT=/path/to/xollvm/bin/opt
cmake --build --preset obfuscated-light
ctest --test-dir build/obfuscated-light --output-on-failure
```

Linux 插件可加 `-DANTI_REA_XOLLVM_PLUGIN=/path/to/Obfuscator.so`。能力探测仅证明 pass 可用，不证明二进制来自预期源码；记录压缩包摘要、版本和独立来源证据。

精简包可能缺 `llvm-cxxfilt`，Linux 可用 GNU `c++filt`；Windows 可用 `llvm-undname`，也可用本项目 DbgHelp 回退，见 [Windows 指南](windows.zh-CN.md)。反修饰器处理名称，不解析 IR，无需与 opt 主版本一致。

## 函数选择

| 等级 | `policy_dispatch` | `policy_token` | 数值热点 |
| --- | --- | --- | --- |
| NONE | 原样 | 原样 | 原样 |
| LIGHT | 低预算 MBA、替换、拆分 | 相同轻量变换 | 原样 |
| MEDIUM | 更多 MBA、替换、拆分、伪分支 | 相同中级变换 | 原样 |
| HEAVY | MBA、伪分支、flattening、shield、有限 adec | 相同重级变换 | 原样 |
| MIXED_VM | MBA、拆分、flattening | VM light | 原样 |

策略 TU 启用模块级 `strenc`，函数注解不意味着只处理该函数的字符串。模块故意较小，其他 TU 的加密诊断不依赖此 pass。VM 和 flattening 不作用于同一函数；关闭 VM 反调试与硬化时间陷阱，避免干扰验证调试器。

## 流水线与证据

Python launcher 固定种子、确定性模式、上游验证和指令预算，恰好调用一次 `opt -passes=obfuscation,verify`。不要同时给 Clang 加 `-enable-obfuscation`，否则重复执行。普通项目直接用编译器时的显式开关见[保护接入（英文）](protection-skill/references/integration.md)。

每个对象独立报告。launcher 校验已知 schema、两个目标函数的证据，所需 VM/flattening 缺失或 skipped 即失败。HEAVY/MIXED_VM 要求 `policy_dispatch` flattening，MIXED_VM 要求 `policy_token` VM；HEAVY 的单块 token 可合理跳过 flattening，表达式变换仍可执行。

检查 `build/<configuration>/private/ir/*/xollvm.json` 及 `private/maps/*.json`；矩阵记录真实目录。原始报告含标识，发布前审查。构建成功不足验收，需精确计算、RTTI、异常、诊断、搬迁及安装后敏感原名扫描，VM 校验和须匹配未修改整数参考。

## 成本与限制

复杂 IR 会增加构建、体积、启动和 CPU 开销。强度标签不是抗逆向强度测量，指令增长、性能和泄露计数分开报告。

strenc 在初始化时解密，程序具备恢复机制，内存可见明文；不同于私钥不在程序内的公钥密封。VM 可跳过 EH、复杂 CFG 或过多块，报告和失败门槛防止误报成功。无基准依据不对数值热点重混淆。

原生 Windows 验证脚本支持在原有工具链和依赖参数后增加 `--obfuscation MIXED_VM`，
原始对照配置仍为 `NONE`。已测的运行行为、REA 恢复边界及 VM/flattening 合计成本见
[Windows 验证记录](windows-validation.zh-CN.md)。
