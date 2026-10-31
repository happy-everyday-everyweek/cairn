# Cairn 测试接缝

本文件是 TDD 的接缝清单，也是这份代码唯一的对外契约。所有测试只打在这里列出的公开接口上，不触碰内部实现。当前状态：133 个用例，Linux、Windows、macOS 三个平台在 CI 上全部通过，Android debug APK 每次推送都会构建。

## 分层：两层门面，一层引擎

对外只有两层。`include/cairn/cairn.h` 是应用平时用的门面，`include/cairn/bundle.h` 是离线包，两者合计 27 个函数，其中 11 个覆盖日常路径：open、pair_wait、pair_join、poll、is_ready、send、send_file、send_chunk、transfer_done、progress、close。其余头文件是引擎与底层组件，供需要自己驱动协议的应用使用。

## 基础密码学：include/cairn/crypto.h

六个原语，全部 vendored，不手写：BLAKE2b（哈希、MAC、KDF、口令拉伸）、XChaCha20-Poly1305、X25519、Ed25519、ML-KEM-768、随机数。

验证方式不依赖被测代码：BLAKE2b 对照 RFC 7693 附录 A 与 Python hashlib，AEAD 对照 PyNaCl/libsodium 向量，X25519 对照 RFC 7748 §6.1，Ed25519 对照 RFC 8032 §7.1，ML-KEM 做往返一致性与错误密钥拒绝。

## 分层混淆：include/cairn/nested.h

由口令派生会话、加密、解密。定位是流量混淆层，机密性由外层 AEAD 承担，头文件里写明了这一点。三个不变量被测试固定：同口令同盐派生出同一会话；同一明文两次封装字节不同；任意一字节被翻转都必须被拒绝。

## 身份：include/cairn/identity.h

身份生成、公钥导出、指纹、六位安全码、公钥序列化。安全码测试双向对称，因为两个指纹先排序再哈希。指纹覆盖全部公钥字段，任一字节变化都必须改变指纹。

## 会话：include/cairn/session.h

X3DH 形状的握手（三方 DH 排序拼接加 ML-KEM 混入），加真 DH 棘轮。要求：链密钥每条消息推进；跨 8 条消息必须换新棘轮公钥；重放被拒绝；乱序最多保留 32 个消息密钥；未确认的对端不能拿到明文。

## 帧格式：include/cairn/wire.h

帧编码、帧解码、CRC-32 校验。截断、坏 magic、坏版本、超长长度、坏校验和都必须返回明确错误码而非崩溃。

## 传输：include/cairn/transfer.h

分包状态机、确认、断点续传。核心测试是断点续传：确认前 4 块后中断，恢复后必须从第 4 块继续，且进度不回退。重复确认幂等，越界确认被拒绝。

## 发现：include/cairn/discovery.h

信标编码解码、邻居表增删查、过期清理。信标里的名字长度字段不可信，超长必须拒绝；名字超长在编码侧被截断而不是拒绝。

## 蓝牙与 Wi-Fi 直连：include/cairn/ble.h、include/cairn/p2p.h

平台无关的虚表，各平台填实现，测试用内存模拟实现验证状态机，因此不需要硬件。BLE 覆盖扫描、广播、连接、收发、数据回调；Wi-Fi Direct 覆盖发现对端、建立群组、获取群组所有者地址、断开。

## NAT 穿透：include/cairn/nat.h

STUN 绑定请求构造与响应解析（同时支持 MAPPED-ADDRESS 与 XOR-MAPPED-ADDRESS），打洞状态机，超时转中继。测试包按 RFC 5389 手写构造，不联网。

## 引擎：include/cairn/protocol.h

把发现、密钥交换、握手、会话、传输组装成可运行节点。引擎不持有 socket，只接受帧、产出帧，所以两个内存节点就能跑完整链路。测试覆盖：信标互相发现、三段握手、被动接受 HELLO、消息端到端、篡改拒绝、文件流式传输、中断后续传、配对码不匹配必须失败。

## 配对决策：include/cairn/protocol.h 中的 cairn_pair_next

配对要发什么帧被抽成纯函数，输入是 peer 状态、是否已有公钥、是否该由我方发起、两个到期标志，输出是三条指令之一：等待、发 KEY、发 HELLO。表驱动测试覆盖了每个分支，其中包括曾经真的让配对卡死的两个组合：有 id 但还没有公钥、以及失败后重新发起。

## 门面：include/cairn/cairn.h

单节点契约：open/close 的生命周期、配对码形状校验（4 到 12 位数字）、未配对时发送必须返回 CAIRN_ERR_STATE、垃圾帧不能破坏节点。这些用例只跑一个节点，证明不了两个节点能配上，所以还需要下一条。

## 真实 socket 上的双节点配对：tests/test_pair_live.c

两个线程各跑一个门面节点，走真实 UDP socket，断言三条：同码必须配上、异码必须拒绝、配上之后一条消息必须送达。这一条用例是唯一能发现“门面从不发起握手”“绑定端口与广播端口不一致”“自己发出的信标被当成对端地址”这类缺陷的探针，因为这些缺陷在所有引擎层测试里都不可见。

它需要宿主机把一个 UDP 包从一个 socket 投递给同机另一个 socket。多数系统可以，少数 CI 镜像不行；不行的时候用例报 SKIP 并给出原因，而不是假装通过或假装失败。

## 离线包：include/cairn/bundle.h

一次性 X25519 私钥与接收方静态公钥做 DH 派生包裹密钥，发送方随即丢弃私钥，因此只有目标设备能解开。每块独立 AEAD，索引与长度进 AAD，防重排与截断；整包再用 Ed25519 签名。测试覆盖：往返一致、错误身份解包返回 CAIRN_ERR_AUTH、改一字节被拒、块被换位被拒、流式接口与一次性接口结果一致、cairn_bundle_size 与实际长度相等。

## 演示程序

`cli/main.c` 是真实 UDP 上的演示，子命令为 `key`、`pair`、`send`、`put`、`seal`、`open`。`android/` 是 Android demo，JNI 桥只做转发，socket 由门面持有，权限由 Kotlin 侧声明。两处都由 CI 构建，不在开发机上编译。
