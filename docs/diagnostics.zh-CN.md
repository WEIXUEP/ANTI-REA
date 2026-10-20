# 诊断保密与恢复

[English](diagnostics.md) | 简体中文

## 数据流

```text
私有密钥 + 源码诊断目录                         仅开发环境
               |
               v
构建生成器 -> 密封 C++ 头文件 -> 编译器 -> 可执行文件 + 公钥
      |
      +-> 私有位置映射                              |
                                                    v
                                   运行字段 -> 密封事件 -> 日志
                                                    |
私钥 + 对应发布映射 -> 离线解码器 <-------------------+
```

生成器在 CMake 配置时读取 JSON 诊断目录并定位具名调用点。保护头文件不含消息模板明文。这比编译后识别任意格式化 C++ 表达式更简单。

运行时将已加密模板、site ID 和格式化动态字段放入 envelope，再用 libsodium `crypto_box_seal` 密封，输出 Base64。只有公开级别、不透明位置及载荷框架保留明文。

解码器先打开 envelope，再打开模板，检查密钥和构建映射并替换字段。sealed box 随机化，同消息不保证相同密文；它不是数字签名，不认证发送者。

## 示例

普通输出：

```text
Engine warning
Diagnostic ID: E-<stable-site-id>
Internal spectral preconditioner stalled after 37 iterations
File: examples/main.cpp
Line: <source-line>
```

保护输出形式如下，占位符不是测试向量：

```text
Engine warning
Diagnostic ID: E-<stable-site-id>
File: F-<opaque-file-id>
Line: L-<opaque-line-id>
Payload: AR1:<public-key-id>:<randomized-base64-ciphertext>
```

生成真实 token 并恢复，无需手动复制密文：

```bash
python - <<'PY'
from pathlib import Path
import subprocess
program = 'build/protected/bin/anti-rea-demo'
log = subprocess.run([program, 'warning'], capture_output=True, text=True, check=True).stderr
token = next(line.split('Payload: ', 1)[1] for line in log.splitlines() if line.startswith('Payload: '))
subprocess.run(['python', 'tools/anti_rea.py', 'decode', '--build', 'build/protected', '--token', token], check=True)
PY
```

恢复结果含原始消息、数值 `37`、源文件、行、site 和公开错误类型。通过 compare 构建时，使用矩阵结果记录的实际构建目录。

## 密钥与映射

`demo-keys/keys.json` 是公开、确定性的教学密钥，文件本身有警告，对仓库读者没有保密性。`keys --out .private/keys.json` 随机生成 master 和独立 Curve25519 密钥对，不覆盖已有文件。RTTI、文件、行使用独立 HMAC 域。

`private/compiler-keys.json` 含公钥及构建期命名 master，**不含解密私钥**，均不安装。master 供构建工具使用，不嵌入程序；C++ 运行时只需公钥材料。

| 私有产物 | 用途 |
| --- | --- |
| `diagnostics.json` | site 到源码映射及原模板 |
| `compiler-keys.json` | 命名 master 和公钥 |
| `maps/*.json` | 每个对象的原始/不透明 RTTI 及混淆证据 |
| `ir/*/*.ll` | 含原名的私有编译中间文件 |
| `config.json` | 保护和资源配置 |

site ID 基于逻辑名称和规范化项目相对路径，无关行插入不改变它；行 ID 随源码行变化，移动到另一文件会改变 site ID。一个目录项对应一个逻辑位置，其他调用点需新条目。ID 是有密钥标识，不是可单独解密的行号，恢复需匹配映射。

按发布版归档密钥和映射。换钥后重建所有相关对象和共享库，旧日志需旧材料。映射本身也敏感。

## 格式、失败与边界

目录仅支持位置 `{}` 字段，C++ 通过流格式化，Python 恢复替换；不等价于完整 fmt。字面秘密放入目录，不要放在单独格式化的字符串参数里。

加密失败只打印 `Payload: <unavailable>`，不回退明文；致命报告仍 abort，异常 `what()` 使用不透明 ID。baseline 故意保留原位置，保护成功路径只求值条件一次，不求值仅失败使用的字段。需要结合源码到对象检查和二进制扫描，stderr 有密文不足以验收。

报告器仅 CPU，不保证异步信号安全，也未实现 CUDA 设备异常、MPI communicator 路由或线程安全日志聚合；这些接入需单独语义测试。
