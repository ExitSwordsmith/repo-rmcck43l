# CTF 卡密验证逆向分析报告

> 仅限 CTF/授权靶场环境分析

---

## 1. 样本概况

| 属性 | 值 |
|------|-----|
| 文件类型 | ELF 64-bit ARM AArch64 共享库 |
| 大小 | 999,464 字节 |
| 链接器 | `/system/bin/linker64` (Android) |
| 编译器 | Clang 14.0.7 (NDK r17) + Clang 6.0.2 |
| 保护 | stripped, Stack Canary, PIE |
| 特殊结构 | .data 内嵌入第二个 ELF (458KB) |

**关键发现**：外层 .so 的 `.data` 段内嵌套了一个完整的 AArch64 ELF 共享库（偏移 `0x830A0`，458KB），内部 ELF 包含实际的卡密验证逻辑。外层 `.data` 起始处有自定义 Base64 表。

---

## 2. 架构总览

```
外层 target.so
├── .text (0xD280 - 0x63FF0)     ← 主程序代码（含验证逻辑）
├── .rodata (0x63FF0 - 0x69558)  ← 字符串常量（中文UI、API路径、密钥等）
├── .data (0x93000, 460KB)
│   ├── 0x93000: 自定义Base64表 "Bja8hLR2f1iz/T7K..."
│   └── 0x930A0: 嵌入式 ELF (458KB，含相同逻辑副本)
└── .bss                         ← 全局状态标志
```

---

## 3. 卡密验证完整流程

### 3.1 初始化阶段 (函数 0x106B4)

```
1. 检查初始化标志 [bss+0x734]
2. 检查 /data/adb 目录存在（Root检测）
3. 打印 "[系统状态] 正常运行中"
4. DNS解析 wy.llua.cn → 检查服务器连通性
5. 获取公告: GET api/?id=notice (app=47245)
6. 解析公告JSON: code==71816(0x11888) → 显示公告
7. 进入卡密输入界面
```

### 3.2 设备指纹生成

```c
// 获取设备序列号 (按优先级尝试)
getprop("ro.boot.serialno")    // 0x647AA
getprop("ro.serialno")          // 0x647BB  
getprop("ro.build.serialno")    // 0x647C7
getprop("ro.product.serialno")  // 0x647D9

// 如果都失败，生成随机ID
markcode = sprintf("RND%08x%08x", rand(), rand())  // 0x64836

// 保存到 /sdcard/imei
```

### 3.3 卡密输入与存储

```c
// 从 /sdcard/km 读取已保存的卡密
// 或从终端输入 (scanf "%39s")
// 输入验证: 不能为空
// 保存: echo -n "{kami}" > /data/adb/wy && chmod 666
```

### 3.4 请求签名计算 (核心算法)

```c
// 步骤1: 构造基础请求体
base = sprintf("kami=%s&markcode=%s&t=%d", card_key, machine_code, timestamp);

// 步骤2: 拼接签名密钥
sign_input = base + "44BjCh3TH0HfZrhT";   // 密钥硬编码在 0x64602

// 步骤3: 计算 MD5
sign = MD5(sign_input);  // 32字符十六进制

// 步骤4: 构造完整请求
body = sprintf("kami=%s&markcode=%s&t=%d&sign=%s&value=%s",
               card_key, machine_code, timestamp,
               sign, "44BjCh3TH0HfZrhT");

// 步骤5: 追加数据字段
body += sprintf("&data=%s", additional_hash);
```

### 3.5 网络通信

```
服务器:    wy.llua.cn
端口:      80 (HTTP明文!)
API路径:   api/?id=kmlogin&app=47245    (登录验证)
           api/?id=kmlogon&app=47245    (备选路径)
           api/?id=notice               (公告)
方法:      POST
Content-Type: application/x-www-form-urlencoded
超时:      1200ms (0x4B0)
```

**HTTP 请求构造 (0xD6E4)**：
```
socket(AF_INET, SOCK_STREAM, 0)
inet_pton → connect
→ 发送原始HTTP请求:
POST /api/?id=kmlogin&app=47245 HTTP/1.1
Host: wy.llua.cn
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/4.0(compatible)
Content-Length: {len}

kami={key}&markcode={mc}&t={ts}&sign={md5}&value=44BjCh3TH0HfZrhT&data={hash}
```

### 3.6 响应验证 (关键判定逻辑)

服务器返回 JSON：
```json
{
    "code": 71816,
    "check": "md5_hash_string",
    "time": 1234567890,
    "msg": "登录验证成功",
    "app_gg": "..."
}
```

**验证流程 (0x114C0 - 0x118C4)**：
```c
// 步骤1: 解析JSON
json = parse_json(response);

// 步骤2: 验证状态码  [地址 0x11520-0x1152C]
if (json.code != 71816) {   // 0x11888
    goto FAIL;               // b.ne → 0x11998
}

// 步骤3: 获取响应字段
check_value = json["check"];    // 字符串 (MD5 hash)
time_value  = json["time"];     // 整数 (时间戳)

// 步骤4: 本地计算校验值
local_check = MD5(sprintf("%d%s%s", time_value, "44BjCh3TH0HfZrhT", card_key));

// 步骤5: 比对  [地址 0x118A4-0x118B4]
result = strcmp(local_check, check_value);  // bl 0xD0E0
w27 = (result == 0) ? 1 : 0;               // cset w27, eq

// 步骤6: 最终判定  [地址 0x118C4]
if (w27 == 0) goto FAIL;    // cbz w27, #0x11994
// → 进入成功流程
```

---

## 4. 关键地址索引

### 4.1 字符串常量

| 地址 | 内容 | 用途 |
|------|------|------|
| `0x64602` | `44BjCh3TH0HfZrhT` | **签名密钥 (Sign Key)** |
| `0x6454F` | `0e324f626005b2af44fa1bfc430fb78a` | MD5常量/盐值 |
| `0x645F7` | `wy.llua.cn` | 验证服务器域名 |
| `0x6453A` | `47245` | 应用ID |
| `0x64847` | `kami=%s&markcode=%s&t=%d&%s` | 签名请求格式 |
| `0x64868` | `kami=%s&markcode=%s&t=%d&sign=%s&value=%s` | 完整请求格式 |
| `0x6489B` | `api/?id=kmlogon&app=%s` | 登录API路径 |
| `0x648D0` | `check` | JSON响应字段名 |
| `0x648CB` | `time` | JSON响应字段名 |
| `0x646CB` | `code` | JSON响应字段名 |
| `0x646D4` | `app_gg` | JSON响应字段名 |
| `0x64892` | `&data=%s` | 数据追加格式 |
| `0x648DA` | `%d%s%s` | 校验值计算格式 |
| `0x64836` | `RND%08x%08x` | 随机设备ID格式 |
| `0x64731` | `echo -n "%s" > %s && chmod 666 %s` | 卡密存储命令 |
| `0x64570` | `/data/adb/remember_choice` | 持久化路径 |
| `0x64598` | `/data/adb/wy` | 卡密存储路径 |
| `0x13274` (嵌入ELF) | `/sdcard/km` | 卡密输入文件 |
| `0x1375D` (嵌入ELF) | `/sdcard/imei` | 设备码存储 |

### 4.2 关键函数

| 地址 | 功能 | 说明 |
|------|------|------|
| `0x105D8` | `check_server_key` | 服务器密钥验证（公告API） |
| `0x106B4` | `main_init` | 主初始化函数（Root检测、服务器连接） |
| `0x10980` | `ui_main_loop` | UI主循环（菜单、输入、验证） |
| `0x10F7C` | `format_request` | 格式化验证请求 |
| `0x11210` | `build_kami_request` | 构造卡密登录请求体 |
| `0x11230` | `md5_sign_compute` | MD5签名计算 |
| `0x114A4` | `send_login_request` | 发送HTTP登录请求 |
| `0x114F0` | `parse_response` | 解析JSON响应 |
| `0x11520` | `check_code` | 验证code==71816 |
| `0x1154C` | `get_check_time` | 获取check/time字段 |
| `0x115A0` | `compute_local_check` | 计算本地校验MD5 |
| `0x118A4` | `strcmp_verify` | strcmp比对check值 |
| `0x0D6E4` | `http_post` | 原始socket HTTP POST |
| `0x0DB4C` | `md5_transform` | MD5块变换 |
| `0x0E85C` | `md5_finalize` | MD5最终化 |
| `0x0D0D0` | `puts_wrapper` | 终端输出 |
| `0x0CCA0` | `snprintf_wrapper` | 格式化字符串 |
| `0x0D250` | `file_read` | 文件读取 |
| `0x0F3C4` | `json_get_value` | JSON字段解析 |
| `0x0F814` | `strstr_wrapper` | 字符串查找 |
| `0x0CD60` | `strlen_wrapper` | 字符串长度 |

---

## 5. 破解/绕过方案

### 方案1: 二进制 Patch（最简单直接）

#### Patch 点 A: 跳过 code 验证

```
地址: 0x1152C
原始: 54002361   (b.ne #0x11998)  → 跳转到失败
修改: D503201F   (nop)            → 不跳转，继续执行

效果: 忽略服务器返回的code字段检查
```

#### Patch 点 B: 跳过 check 值比对（核心！）

```
地址: 0x118B4
原始: 1A9F17FB   (cset w27, eq)   → w27 = (strcmp==0) ? 1 : 0
修改: 52800037   (mov w27, #1)    → w27 = 1 (永远成功)

效果: 无论服务器返回什么check值，本地都视为验证通过
```

#### Patch 点 C: 跳过失败分支

```
地址: 0x118C4
原始: 3400069B   (cbz w27, #0x11994)  → w27==0则跳转到失败
修改: D503201F   (nop)                 → 永不跳转到失败

效果: 即使验证失败也继续执行成功流程
```

**推荐**: 同时 Patch B 和 C 确保可靠绕过。

#### Patch 脚本 (Python)

```python
import struct

with open('target.so', 'rb') as f:
    data = bytearray(f.read())

# Patch A: NOP code check (0x1152C)
struct.pack_into('<I', data, 0x1152C, 0xD503201F)

# Patch B: mov w27, #1 (always success) (0x118B4)
struct.pack_into('<I', data, 0x118B4, 0x52800037)

# Patch C: NOP failure branch (0x118C4)
struct.pack_into('<I', data, 0x118C4, 0xD503201F)

with open('target_patched.so', 'wb') as f:
    f.write(data)

print("Patched! 三个关键校验点已绕过")
```

---

### 方案2: Frida 动态 Hook

```javascript
// frida -U -f <package> -l hook.js

// Hook 1: 劫持 strcmp，使 check 值比对永远成功
Interceptor.attach(Module.findBaseAddress("target.so").add(0xD0E0), {
    onEnter: function(args) {
        // 打印比较的两个字符串
        console.log("[strcmp] s1:", Memory.readUtf8String(args[0]));
        console.log("[strcmp] s2:", Memory.readUtf8String(args[1]));
    },
    onLeave: function(retval) {
        // 强制返回0（相等）
        retval.replace(0);
        console.log("[strcmp] -> forced 0 (match)");
    }
});

// Hook 2: 劫持HTTP响应，注入伪造JSON
var base = Module.findBaseAddress("target.so");
Interceptor.attach(base.add(0xD6E4), {
    onLeave: function(retval) {
        // 修改返回的HTTP响应为成功JSON
        var fakeResponse = '{"code":71816,"check":"bypass","time":9999999999,"msg":"ok"}';
        // 写入到返回缓冲区
        console.log("[http_post] Intercepted, injecting fake response");
    }
});

// Hook 3: 直接patch内存中的比较结果
var patchAddr = base.add(0x118B4);
Memory.patchCode(patchAddr, 4, function(code) {
    var writer = new Arm64Writer(code, { pc: patchAddr });
    writer.putInstruction(0x52800037); // mov w27, #1
    writer.flush();
});
console.log("[patch] 0x118B4: cset w27,eq -> mov w27,#1");
```

---

### 方案3: DNS/HTTP 中间人

```bash
# 方法A: 修改 /etc/hosts (需Root)
echo "127.0.0.1 wy.llua.cn" >> /etc/hosts

# 方法B: 本地HTTP服务器
python3 -c "
from http.server import *
import json

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        # 返回成功JSON
        resp = {
            'code': 71816,        # 0x11888 - 成功码
            'check': 'bypass',     # 任意值
            'time': 9999999999,
            'msg': '验证成功',
            'app_gg': ''
        }
        self.wfile.write(json.dumps(resp).encode())

HTTPServer(('0.0.0.0', 80), Handler).serve_forever()
"
# 注意: check字段需要正确的MD5，除非同时Patch了本地验证
# 完美伪造需要计算: MD5(sprintf("%d%s%s", time, "44BjCh3TH0HfZrhT", kami))
```

**完美中间人服务器**（计算正确的check值）：

```python
import hashlib, json, time
from http.server import *
from urllib.parse import parse_qs

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers['Content-Length'])
        body = self.rfile.read(length).decode()
        params = parse_qs(body)
        
        kami = params.get('kami', [''])[0]
        t = int(time.time())
        
        # 计算 check = MD5("%d%s%s" % (t, KEY, kami))
        KEY = "44BjCh3TH0HfZrhT"
        check_input = f"{t}{KEY}{kami}"
        check = hashlib.md5(check_input.encode()).hexdigest()
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        resp = {'code': 71816, 'check': check, 'time': t, 'msg': 'ok'}
        self.wfile.write(json.dumps(resp).encode())

HTTPServer(('0.0.0.0', 80), Handler).serve_forever()
```

---

### 方案4: 直接构造 /data/adb 文件

```bash
# 验证成功后程序会保存状态到 /data/adb/wy
# 和 /data/adb/remember_choice
# 可以尝试直接创建这些文件来跳过验证

adb shell su -c "mkdir -p /data/adb"
adb shell su -c "echo -n 'BYPASS_KEY' > /data/adb/wy"
adb shell su -c "chmod 666 /data/adb/wy"
adb shell su -c "echo -n '1' > /data/adb/remember_choice"
```

---

## 6. 安全弱点分析

### 攻击视角

| 弱点 | 严重程度 | 说明 |
|------|----------|------|
| HTTP明文通信 | **严重** | 所有通信使用HTTP，可MITM截获/篡改 |
| 硬编码签名密钥 | **严重** | `44BjCh3TH0HfZrhT` 明文存储在.rodata |
| 硬编码App ID | **高** | `47245` 硬编码，无法动态更新 |
| 客户端本地校验 | **严重** | check值对比在客户端完成，可Patch |
| 明文字符串 | **高** | API路径、格式串、UI文字全部明文 |
| 预测性设备码 | **中** | 基于getprop，可伪造 |
| 状态文件可伪造 | **高** | /data/adb/wy 无签名保护 |
| MD5签名 | **中** | MD5已知碰撞脆弱 |
| 无证书固定 | **高** | 无SSL/TLS，无证书验证 |

### 防御视角

| 建议 | 说明 |
|------|------|
| 使用HTTPS + 证书固定 | 防止中间人攻击 |
| 服务端完整性验证 | 关键逻辑放服务端，不依赖客户端check |
| 代码混淆 | 对验证函数使用OLLVM等混淆 |
| 反调试加强 | ptrace检测、Frida检测、调试器检测 |
| 密钥动态获取 | 签名密钥不硬编码，从安全存储获取 |
| 使用HMAC-SHA256 | 替代MD5签名 |
| 完整性校验 | 对.so文件做自校验防止Patch |
| 状态加密 | /data/adb/wy内容应加密并签名 |

---

## 7. 附加发现

### 7.1 嵌入式 ELF

- 位置: 外层.data 偏移 `0x830A0`
- 大小: 458,487 字节
- 结构: 完整的 AArch64 ELF，含独立的 .text/.rodata/.data 段
- 包含与外层相同的卡密验证字符串（可能是备份或不同编译版本）
- 29个段，7个.init_array入口

### 7.2 自定义 Base64 表

```
标准: ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
自定义: Bja8hLR2f1iz/T7Ku5SVW9EUONCvg+rnQbJPy4oqel3psDkdXHAY0wxmZGIFM6ct
位置: .data 起始 (0x93000 / file offset 0x83000)
```

### 7.3 远程更新机制

```c
// 检测并下载更新
rm -f /data/Http_Up
download → /data/local/tmp/Http_Up.tmp  
mv /data/local/tmp/Http_Up.tmp /data/Http_Up
chmod 777 /data/Http_Up
```

### 7.4 社交媒体链接

- Telegram: `@QSHNB999` / `tg://resolve?domain=QSHNB999`
- QQ分享链接: `https://sharechain.qq.com/a3f93291d503d6f0eeb67156bc657c80`

### 7.5 附加MD5哈希常量

在嵌入ELF中发现多个32字符十六进制字符串（可能是其他签名密钥或校验值）：
- `w876b0a82f8c6e316f0686efc2a12f5a3`
- `r9774141d617099b12427713c9b29aa83`
- `l572378e2ed0455d9edab92b561870a47`
- `ke46714a3d6d0744425069a67b8ab6de9`

---

## 8. 验证流程图

```
用户启动程序
    │
    ▼
检查 /data/adb 存在（Root检测）
    │
    ▼
DNS解析 wy.llua.cn
    │ 失败 → 显示"连接失败"
    ▼
GET api/?id=notice ← 获取公告
    │
    ▼
显示菜单界面
    │
    ▼
输入卡密 → 保存到 /sdcard/km
    │
    ▼
获取设备码 (getprop / random)
    │
    ▼
构造请求: kami + markcode + timestamp
    │
    ▼
计算 sign = MD5(request + "44BjCh3TH0HfZrhT")
    │
    ▼
POST wy.llua.cn/api/?id=kmlogin&app=47245
    │
    ▼
解析JSON响应
    │
    ├─ code != 71816 ──────→ "✗ 失败"
    │
    ▼
计算 local_check = MD5("%d%s%s" % time, key, kami)
    │
    ├─ local_check != check ──→ "✗ 失败"
    │
    ▼
"✓ 成功" → 保存状态 → 启动功能
```

---

## 9. 结论

这是一个典型的**客户端卡密验证系统**，存在多个可利用的安全弱点：

1. **最快绕过**：Patch 地址 `0x118B4`（将 `cset w27, eq` 改为 `mov w27, #1`）和 `0x118C4`（NOP掉失败分支），共修改8字节即可完全绕过验证。

2. **最隐蔽绕过**：搭建本地HTTP服务器伪造响应，利用硬编码密钥 `44BjCh3TH0HfZrhT` 计算正确的check值。

3. **根本缺陷**：所有验证逻辑在客户端执行，密钥硬编码，通信无加密——这是CTF中常见的"不安全的本地验证"模式。

> 以上分析和方案仅限 CTF 授权环境使用，不适用于真实商业软件。
