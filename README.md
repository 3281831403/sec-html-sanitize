富文本编辑器保存的评论里，总能塞进一段能跑的脚本：标签白名单用 startswith 判断，scriptx 因此混进白名单；事件属性没有剔除，onclick 直接执行；只按小写剔除事件属性，OnClick 这种大小写混写照样保留；URL 协议判断前不解 HTML 实体，用实体拼出来的 javascript 协议能过；协议判断只看前缀，中间夹制表符的写法也过；data 协议没有限制类型，data 加 text/html 可执行；文本转义漏掉单引号，属性上下文可以逃逸；注释不做递归处理，注释里的脚本标签被保留；策略校验不检查 style 属性与其他危险属性；批量净化复用策略缓存，后一个片段带上一个片段的脏状态。sanitize/html.py 是核心，tests/test_html.py 15个红。要修的是：按上面的顺序把 10 个缺陷逐个修掉。

## 运行方式

在仓库根目录执行：

```bash
python -m pytest tests -q
```

初始失败环境必须恰好输出 `15 failed`，不能出现 collection error、import error 或 syntax error，也不能有 skipped 或 passed。15 个测试都因为桩函数抛出 `NotImplementedError` 而失败：

```text
15 failed in <time>
```

修复后，同一个命令应变为 `15 passed`。

## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |

## 文件

```text
sec-html-sanitize/
├── README.md
├── conftest.py
├── .gitignore
├── sanitize/
│   ├── __init__.py
│   └── html.py
└── tests/
    └── test_html.py
```

## 约束

- **`tests/test_html.py` 不可修改。** 只能改 `sanitize/` 下的实现；15 个测试是固定契约。
- 只使用 Python 标准库 `re`、`html`、`urllib.parse` 与 `pytest`，不联网、无随机、无第三方依赖。
- 所有匹配都按大小写不敏感、整名精确匹配处理；`allowed_tag` 不得用 `startswith`，`safe_url` 不得用协议前缀比较。
- 标签/属性白名单之外的内容必须丢弃或解包；`script`、`style`、事件属性不得出现在输出中。
- URL 必须先解 HTML 实体并去除可忽略空白，再按协议白名单判断；`data:` 只允许安全的位图 MIME，`data:text/html` 与 `data:image/svg+xml` 必须拒绝。
- 文本和属性值必须转义 `<`、`>`、`&`、`"`、`'`；注释与 DOCTYPE 整段丢弃。
- `sanitize_batch` 的每个片段独立净化，禁止复用上一片段的缓存或改写 `policy`。
- 实现与测试的容差为 0；唯一显式例外是纯文本不变性检查使用 `1e-9` 的相对漂移上限（正确实现的实际漂移为 0）。
