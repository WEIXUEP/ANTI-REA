# 代码保护 Skill

[English](using-protection-skill.md) | 简体中文

`cpp-code-protection` 指导限定范围的 C++ 保护实现、密钥管理、离线恢复和工作负载测量。它独立于只读[检测 skill](audit-skill.zh-CN.md)，不附带扫描器。

## 安装与能力

[下载 cpp-code-protection](downloads/cpp-code-protection.zip)，解压到代理 skill 目录，或复制 `skills/cpp-code-protection`。Python 3.10+ 可运行独立工具；PyNaCl 支持兼容的密钥生成和密封事件恢复，不依赖示例仓库。代理入口为 `SKILL.md`，skill 及其参考文档保持英文。

| 能力 | 入口 |
| --- | --- |
| 检查依赖及 LLVM/xollvm | `scripts/doctor.py` |
| 生成私有恢复材料 | `scripts/generate_keys.py` |
| 恢复支持格式的诊断、位置、RTTI | `scripts/decode.py` |
| 测量可信目标工作负载 | `scripts/measure.py` |
| C++ 保护和选择性混淆 | 代理依据参考文档修改目标 |
| 解码 GUI 设计 | 基于共享后端的设计指导，未附带 GUI |

```bash
python <skill-directory>/scripts/doctor.py
python <skill-directory>/scripts/generate_keys.py --out /private/r17/keys.json
python <skill-directory>/scripts/decode.py --build /private/r17/build \
  --keys /private/r17/keys.json --report warning.log
python <skill-directory>/scripts/decode.py --build /private/r17/build --list-maps
python <skill-directory>/scripts/measure.py --config workloads.json \
  --samples 9 --warmups 2 --out /private/reports/workloads
```

生成器和解码器支持文档中的示例 schema，不支持任意产品格式。原名映射不是加密载荷，查表成功不等于解密。运行时只携带诊断加密公钥，私钥、命名密钥、映射、IR 和调试文件不能进入部署包。

## 给代理的请求示例

```text
使用 $cpp-code-protection 规划此 C++ 引擎的保护，暂不修改。
保留公共 ABI、异常和 RTTI 行为，明确中央诊断接口、目标及消费者覆盖、密钥存储和验收测试。
```

```text
使用 $cpp-code-protection 实施已授权的一方代码保护。
启用发布剥离及诊断、位置、RTTI 基础保护。
额外混淆按函数价值和实测预算选择，保留数值热点。
重建、测试恢复，并用原始敏感语料重新检查全新安装包。
```

仅设计任务不包含生成密钥或构建。现有审计工具也可提供 baseline 和最终证据，检测 skill 不是前置依赖。

## 规范说明

- [Skill 说明（英文）](protection-skill/index.md)
- [独立操作（英文）](protection-skill/references/operations.md)
- [接入契约（英文）](protection-skill/references/integration.md)
- [修复与函数选择（英文）](protection-skill/references/remediation.md)
- [密钥生命周期（英文）](protection-skill/references/key-management.md)
- [离线恢复和 GUI（英文）](protection-skill/references/recovery-tools.md)
- [验证（英文）](protection-skill/references/validation.md)
- [Windows 验收（英文）](protection-skill/references/windows.md)

下载包采用显式白名单并在仓库外测试。加密、不透明命名、剥离、混淆针对不同通道，不能保证原生代码无法逆向。
