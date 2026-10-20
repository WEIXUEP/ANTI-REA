# 参考项目评估与能力改进

[English](reference-improvements.md) | 简体中文

2026-10-20 对照 [chldbwnstm/ANTI-REA](https://github.com/chldbwnstm/ANTI-REA)，
固定参考提交 `84c4b87a4da583acd30d060bbf01f73ce1e30739`。
参考仓库单独克隆，未替换本项目或引入新的构建依赖；本次改进独立实现，未复制其保护引擎。

## 参考价值与选择

| 参考实现 | 对本项目的价值 | 本次处理 |
| --- | --- | --- |
| `antirea/scope.py` 的调用者、被调用者及共享全局数据审查 | 单独虚拟化核心函数仍会留下包装常量和共享表 | skill 增加周边审查；扫描器增加显式数值语料。尚未实现自动 IR 保护范围推导 |
| `antirea/defense_validate.py` 的工程预算与轮换采样 | 功能正确和性能可接受应分别判定 | Windows 工具及独立测量 skill 增加预算、相对速度及失败退出码 |
| `antirea/judge.py` 的边界、相关输入及独立私有测试 | 区分恢复公式与仅拟合已知样本 | 保留现有边界/holdout 流程；不将参考仓库的结果算作本项目测试 |
| `antirea/hardening.py` 的环境检测、诱饵和商用配置 | 可作为进一步实验选项 | 本次未移植。特别未引入会改变计算结果的静默 key poisoning |

来源分别为固定提交中的
[范围审查](https://github.com/chldbwnstm/ANTI-REA/blob/84c4b87a4da583acd30d060bbf01f73ce1e30739/antirea/scope.py)、
[预算验证](https://github.com/chldbwnstm/ANTI-REA/blob/84c4b87a4da583acd30d060bbf01f73ce1e30739/antirea/defense_validate.py)、
[行为判定](https://github.com/chldbwnstm/ANTI-REA/blob/84c4b87a4da583acd30d060bbf01f73ce1e30739/antirea/judge.py)和
[hardening 模块](https://github.com/chldbwnstm/ANTI-REA/blob/84c4b87a4da583acd30d060bbf01f73ce1e30739/antirea/hardening.py)。
本次审阅未运行参考仓库的 VM、商用工具或外部攻击实验，未复现其 README 的“25%”指标，
不能用它比较两个项目的通用防御能力。

## 数值常量检测

原扫描器着重字符串和元数据。新增 `--constant` 按用户声明的表示查找数值字节，
无需 REA 或反汇编器，可随检测 skill ZIP 独立运行：

```powershell
python skills/cpp-leakage-audit/scripts/audit.py `
  --binary original/app.exe --constant u32le:0x5a827999 `
  --constant f64be:0.125 --require-metadata --out build/private/original
```

支持 `u32le/u32be/u64le/u64be/f32le/f32be/f64le/f64be`，拒绝越界整数及非有限浮点数。
输出类别为 `specified-constant`，记录精确文件偏移，`--fail-on-deny` 可作为发布门槛。
所有数值语料与原有文字语料一样参与 baseline 一致性检查。
扫描器版本已变更，需重新扫描保留的原始产物形成新 baseline，不修改旧报告。

字节命中不证明运行用途、数据类型或所属算法。折叠、拆分和加密后的常量可能不再匹配；
公共或很短的常量可能产生无关命中。skill 要求结合调用者、共享数据和引用审查，
也不根据诱饵函数名、看似密码表的数组就认定真实算法。

## 性能预算

原生 Windows 增加 `--max-bench-slowdown`、`--max-startup-slowdown` 和 `--max-package-ratio`。
独立保护 skill 的测量清单增加可选 `comparisons`：

```json
{"reference": "baseline", "target": "protected", "max_slowdown": 1.25, "max_size_ratio": 2}
```

这些值仅是用法示例。预算在执行前验证并记录，超限返回 1；失败工作负载或缺少有效参考值不能通过。
独立工具还轮换采样顺序、保留每次耗时和 p95、检查预热输出，并在测量后核对声明产物的大小和 SHA-256。
相对速度为 `100 * baseline时间 / protected时间`，与“增加多少耗时”分开报告。
命令格式见[Windows 指南](windows.zh-CN.md)及[测量方法](measurement.zh-CN.md)。

## Windows 实测

复用已验收的 OFF/NONE 与 ON/MIXED_VM 发布包，未重编译、修改目标或执行真实 Palace。
保护 EXE SHA-256 为 `28e69edcd5fe3e231a9479fa56f78a18cc12417ec21d2a0b7fc51f480ad1611b`。

- 原始及保护 EXE 均命中 `u32le:0x5a827999`，文件偏移分别为 28419、33469；逐项读取原始字节复核。
  负对照 `u64le:0x0123456789abcdef` 未命中，结构化元数据没有未检查项。
  保护版的 `--fail-on-deny` 返回 1，正确反映仍有选定常量可见；这不是新增泄露或 RTTI 保护回归。
- 最终原生测量每组预热 3 次、采样 11 次，策略循环中位数为 2.586 / 75.946 ms，
  耗时比率为 29.367，相对速度为 3.405%。预声明 2 倍耗时预算时拒绝；
  另一次以 50 倍预算作宽松正对照时通过（2.578 / 74.792 ms，比率 29.016）。
  50 倍不是建议的生产预算。功能及独立参考值检查均通过。
- 完整暂存包为 576534 / 840726 字节，比率约 1.458，两组均包含 libsodium；2 倍整包预算通过。
  单独的 EXE+engine DLL 比率约 3.324，不能与整包体积比混用。
- 独立 ZIP 工具的真实 Windows `selftest` 测量命中独立预期输出；刻意设置的 0.5 倍体积预算失败并返回 1。
  所有选定 EXE/DLL 测试前后哈希不变。

首次整目录 baseline 比较因资源别名改变、文件清单不同而被拒绝，失败证据保留。
之后常量专项比较明确选择三份同名 EXE/DLL，未把它称为整包比较；体积仍测完整包。
最终从生成的两个独立 skill ZIP 中解压运行工具，通用测量使用 `-I -S` 隔离模式。
92 项回归运行完成，4 项平台/权限检查跳过；两个 skill 格式及 MkDocs 严格构建通过。
最终原生证据为私有 `build/reference-improvements/20261020-r003/results/verification.json`，
首次尝试及后续脚本、响应、快照、原始样本也保留，不随文档或 skill ZIP 发布。
本次没有增加盲测攻击实验，也没有证明常量隐藏或通用去虚拟化能力。
