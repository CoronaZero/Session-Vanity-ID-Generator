# Session-Vanity-ID-Generator

一个使用 Rust 编写的 Session Vanity ID 生成器。

通过多线程不断生成 Session Account ID，并检查是否匹配 `p.txt` 中指定的前缀。命中后会自动保存 Account ID、恢复短语和 Seed。

## 编译

需要安装：

* Rust
* Cargo

克隆仓库后执行：

```bash
cargo build --release
```

编译完成后，可执行文件位于：

```text
target/release/session-id-gen
```

Windows 下为：

```text
target/release/session-id-gen.exe
```

## 使用

准备一个 `p.txt`，每行填写一个希望匹配的 Session ID 前缀，例如：

```text
05AB
05CD
05EF
```

然后准备 Session 使用的 `english.json` 单词表。

> 目前，仓库中的助记词 `english.json` 单词表来源是 <https://raw.githubusercontent.com/session-foundation/session-desktop/dev/mnemonic_languages/english.json>

运行：

```bash
./session-id-gen --threads 4 --patterns p.txt --output found --wordlist english.json
```

Windows：

```powershell
.\session-id-gen.exe --threads 4 --patterns p.txt --output found --wordlist english.json
```

参数说明：

| 参数 | 说明 |
| ------------ | -------------- |
| `--threads` | 使用的线程数量 |
| `--patterns` | 目标前缀文件 |
| `--output` | 命中结果的保存目录 |
| `--wordlist` | Session 助记词单词表 |

程序运行后会持续搜索，按 `Ctrl+C` 可以停止。

## 输出

成功命中后，会在输出目录创建以 Account ID 命名的文件夹：

```text
found/
└── 05xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx/
    ├── account.txt
    ├── recovery_phrase.txt
    └── seed.hex
```

请妥善保管 `recovery_phrase.txt` 和 `seed.hex`，不要公开或提交到 Git 仓库。

## License

MIT
