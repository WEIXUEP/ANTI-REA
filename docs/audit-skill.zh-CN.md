# 泄露检测 Skill

[English](audit-skill.md) | 简体中文

`cpp-leakage-audit` 是独立的只读源码和原生发布包审计 skill，查找诊断、条件、路径、名称、RTTI 和私有产物，依据证据提出建议。可选 REA 将范围扩展到原生安全调查；漏洞候选与已确认信息泄露分别报告。

加密、构建修改、密钥和恢复工具由独立的[代码保护 skill](using-protection-skill.zh-CN.md)负责，二者互不依赖。

## 安装与运行

[下载 cpp-leakage-audit](downloads/cpp-leakage-audit.zip)，解压到代理的 skill 目录，或复制仓库 `skills/cpp-leakage-audit`。不会全局安装任何内容。`SKILL.md` 为代理入口，skill 及其参考文档保持英文。

基本扫描需 Python 3.10+；可选 pyelftools/pefile 提供结构化元数据解析，在选定环境安装 `scripts/requirements.txt`。包内不含密钥生成或目标重写功能。

```bash
python <skill-directory>/scripts/audit.py --source /authorized/source \
  --binary /original/app --binary /original/engine.so \
  --deny-file sensitive-corpus.json --require-metadata \
  --out /private/reports/original
python <skill-directory>/scripts/audit.py --package /staged/release \
  --fail-on-private --require-metadata --out /private/reports/package
```

路径始终检测，指定函数名/变量名默认为空。`--all-strings` 输出私有的全局可读字符串清单。baseline 和报告含敏感证据，禁止安装到发布包。

## 给代理的请求示例

```text
使用 $cpp-leakage-audit 检查源码、原始可执行文件、库和完整发布目录。
任何修改前保存私有 baseline。按偏移或源码行报告诊断、路径、RTTI、符号泄露，
列出有意公开的名称和无法执行的检查。不要修改目标。
```

审计不隐含重编译、strip、生成密钥或安装工具链授权。用户提供修复后的产物时，可用同一语料、顺序和清单比较结果。

## 规范说明

- [Skill 说明（英文）](skill/index.md)
- [操作和退出码（英文）](skill/references/operations.md)
- [结果解释（英文）](skill/references/interpretation.md)
- [验证要求（英文）](skill/references/validation.md)
- [Windows PE 审计（英文）](skill/references/windows.md)
- [REA 子模块、CLI/MCP 和漏洞调查（英文）](skill/references/rea.md)

网站和 ZIP 使用相同的白名单源文件。源码启发式检测不是 C++ 解析器；字节匹配不能证明运行路径，零匹配也不意味着无法逆向。
