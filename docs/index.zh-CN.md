# ANTI-REA

[English](index.md) | 简体中文

可运行的 C++ 信息泄露实验文档：构建示例、检查发布产物、实施限定范围的保护，再用可复现工具比较变化。

!!! warning "保护有边界"
    诊断保密、不透明 RTTI 名称、符号剥离和代码混淆处理不同的信息通道，均不能使原生程序无法逆向。仓库中的示例密钥是公开教学材料，不是生产秘密。

## 从这里开始

| 目标 | 文档 |
| --- | --- |
| 构建和运行示例 | [快速开始](quickstart.zh-CN.md) |
| 了解保护目标 | [威胁模型](threat-model.zh-CN.md)、[场景目录](scenarios.zh-CN.md) |
| 恢复加密警告 | [诊断与恢复](diagnostics.zh-CN.md) |
| 比较三种发布版本 | [测量方法](measurement.zh-CN.md) |
| 查看数值泄露与性能预算改进 | [参考项目评估](reference-improvements.zh-CN.md) |
| 检测其他 C++ 项目 | [检测 skill](audit-skill.zh-CN.md) |
| 接入保护、密钥和恢复 | [保护 skill](using-protection-skill.zh-CN.md) |
| 部署文档 | [GitHub Pages](github-pages.zh-CN.md) |

## 默认策略

新配置启用 `ANTI_REA_CODE_PROTECTION=ON` 和 `ANTI_REA_STRIP_RELEASE=ON`，保护诊断模板、源码位置、内部 RTTI 名称和发布元数据，恢复材料独立保存在内部。

混淆默认 `ANTI_REA_OBFUSCATION=NONE`。按实现价值、调用频率和性能要求选择函数混淆或虚拟化，避免对所有函数使用最昂贵配置。baseline 与 stripped 对照预设故意关闭信息保护。

## 实现与证据

示例包含 EXE 和共享库，检查跨库 RTTI、异常、条件单次求值和搬迁后的资源加载。Python 负责构建期生成、IR 转换、审计和离线解码，CMake 负责构建和安装。

[Linux 结果](comparison.zh-CN.md)来自实测；原生 Windows 的完成范围见[验证记录](windows-validation.zh-CN.md)。Linux 成功不能代替 Windows 验收。解释零敏感匹配前请阅读[剩余暴露](remaining-exposure.zh-CN.md)。
