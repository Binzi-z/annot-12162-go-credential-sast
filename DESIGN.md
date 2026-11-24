# credscan 设计说明

面向「Go 服务仓库硬编码云凭证泄露」事件的静态分析工具。事件复盘确定的四类载体、
三级可信度、跨包传播、SARIF 输出、CI 阻断和指标门槛，全部在本仓库落地为可运行代码。

## 1. 总体架构与事件时间线对应

| 阶段 | 交付物 | 代码位置 |
| --- | --- | --- |
| T+0 止血 | 单文件/单仓库即时扫描，直接产出真实密钥清单用于轮换 | `python -m credscan scan <repo>` |
| T+1 全量清单 | 四类载体全量扫描 + SARIF 报告 + 传播链 codeFlows | `credscan/engine.py`, `credscan/sarif.py` |
| T+7 常态化可测 | 50 样本评测门槛、性能门槛、GitHub Actions 阻断 | `eval/`, `.github/workflows/credscan.yml` |

数据流：

```
文件发现(engine.Scanner)
   |-- *.go ----------------> tree-sitter CST -> 符号表/常量折叠/过程内污点(goparser)
   |-- *.yaml/*.yml --------> 手写缩进语法 parser(textparse.parse_yaml)
   |-- *.json --------------> 手写递归下降 parser(textparse.parse_json，带字节偏移)
   |-- Dockerfile* ---------> 指令 parser + 续行/exec-form(textparse.parse_dockerfile)
   |-- *.sh / Makefile -----> shell 分词器/mini-parser(textparse.parse_shell)
   `-- *.env / *.properties> 行 parser(textparse.parse_envfile)
                                  |
                          仅语法位置产生候选(RawCandidate / PkgSymbol)
                                  |
                    内容判定 secrets.analyze_value -> real/example/placeholder
                                  |
                    夹具降噪 policy.apply_fixture_policy
                                  |
                    Finding -> SARIF v2.1.0 / 退出码阻断
```

## 2. 「禁止正则一把梭、禁止套现成规则集」如何落实

- **Go 侧**：每个候选都诞生于 tree-sitter 的具体语法节点——const/var 说明符的值节点、
  复合字面量的 keyed element、调用实参、选择表达式赋值、参数据。不存在对源码文本的
  正则扫描；字符串只有出现在真实语法槽位时才被解码判定。
- **非 Go 侧**：JSON 用手写递归下降语法分析（同时记录字节偏移以还原行列号）；YAML 用
  手写缩进栈 parser（支持 map/seq/块标量/引号/注释）；Dockerfile 按指令语法解析并处理
  行续接与 exec-form JSON；Shell 自己实现分词器（引号、转义、heredoc、续行）。
- **命名知识只作用于标识符**：`model.is_credential_name` 对 camelCase/snake_case/kebab-case
  分词后的标识符做语义判断（变量名、结构体字段、YAML key、shell 赋值 LHS、HTTP header、
  flag 名），从不作用于文件正文。
- **内容判定不用正则**：云厂商签名是「前缀 + 定长 + 字符集」的结构化谓词；AWS/GCP 风格
  access-key-id 额外做公开的 base32 校验位运算；PEM 校验 fence 标记并对 body 做 base64
  严格解码；JWT 校验三段式并解码 header/payload。
- 不依赖 gitleaks/trufflehog/CodeQL 等任何现成规则集，依赖只有 tree-sitter 运行时与
  tree-sitter-go 语法（解析器，不是规则）。

## 3. 四类载体的覆盖方式

1. **配置常量（Go 源码）**：const/var 声明、const 块表达式继承、iota 跳过、
   字符串拼接常量折叠、包级变量的复合字面量与函数调用。
2. **测试夹具**：`*_test.go`、`testdata/`、`fixtures/`、`mock/`、`example/` 等路径与包名
   信号被收集并附加到 finding；夹具内文件与正常文件走同一套解析，不跳过。
3. **容器镜像层（Dockerfile/compose）**：`ENV`/`ARG`/`LABEL` 赋值、`RUN` 内嵌 shell、
   `CMD`/`ENTRYPOINT` 的 exec-form 与 shell-form、跨行续接。
4. **CI 脚本**：`.github/workflows/*.yml`、`.gitlab-ci.yml`（YAML 语法路径）、shell 脚本的
   `export`/普通赋值/`--flag=value`/`Authorization:` header/heredoc，以及 `.env` 文件。

## 4. 三级可信度判定（real / example / placeholder）

判定在 `credscan/secrets.py`，输入是已解码的字面量值 + 语法位置名：

- **real**：通过厂商结构签名（前缀/长度/字符集）且校验位通过；或 PEM/JWT 体可解码；
  或凭证命名位置上长度 ≥12、归一化熵 ≥0.75 的无空白高熵串。
- **example**：官方文档著名假值（`AKIAIOSFODNN7EXAMPLE` 等，精确/前缀命中，优先级高于
  校验位——文档 key 本身就是校验位合法的）；厂商 test-mode 前缀（`sk_test_`）；
  家族正确但校验位失败的仿冒值；弱证据低置信串。
- **placeholder**：环境变量/模板间接引用（`${X}`、`{{ }}`、`<...>`、`%X%`）；
  `your-*`/`changeme`/`xxxx`/`example` 等占位词；低变化度（≤3 种字符）、通用词、
  凭证位上的短值。

熵采用按实际字符表归一化到 [0,1] 的 Shannon 熵，避免 base64 与纯小写串直接可比的问题。

## 5. 传播追踪：跨包、跨构建标签、跨生成代码

- **符号表**：按 Go import path 建包级符号表，记录每个 const/var 的值语法节点、
  折叠结果、构建约束、生成代码标记、夹具信号。
- **常量折叠**：递归求解字符串 `+` 拼接与符号引用，跨文件/跨包解析 selector
  （`config.AccessKeyID`），循环引用有 folding 守卫；折叠不完整时退化为只报其中
  结构合法的字面量片段。
- **过程内污点**：短变量声明、var 声明、赋值（含选择表达式写 `c.SecretKey = ...`）、
  函数实参、返回值、复合字面量、index/unary/括号/二元表达式的 origin 并集传播；
  sink 由被调函数名的词干语义判定（`sign/request/client/token/s3/...`）。
- **传播链落 SARIF**：常量 origin 与每个使用点组成 `codeFlows.threadFlows`。
- **构建标签**：`buildtags.py` 实现 `//go:build` 布尔文法（`|| && ! ( )`、goos/goarch、
  版本 tag）与 legacy `// +build`；被排除的文件**仍然分析**（标签门控代码可能进入真实
  构建），约束表达式写进 finding 的 `build-constraint` 属性。
- **生成代码**：识别标准 `Code generated ... DO NOT EDIT.` 头，同样不跳过，
  finding 带 `generated-code: true`——事件中镜像层/生成代码正是藏密钥的位置。

## 6. 测试夹具降噪策略（题面专项）

核心原则：**证据优先于上下文，抑制只能降级、不能抹除**。实现见 `credscan/policy.py`。

1. **结构证据一票否决**。证据等级 rank 4（结构签名 + 校验位通过/PEM-JWT 解码）和
   rank 3（结构签名）的 finding，即使出现在 `testdata/`、`*_test.go`、`mock/` 里也永远
   报 real、永不 suppress。生产密钥被误提交进夹具目录正是本工具要抓的场景，不能因路径
   降噪而漏报。
2. **夹具信号只来自语法元数据，不靠猜内容**：目录名、`_test.go` 后缀、包名、CI job 名。
   信号逐条附在 finding 上并写进 SARIF，可审计。
3. **只有弱证据可抑制**。rank ≤2（纯熵、无结构签名）的 real 判定，在强路径信号
   （`testdata/`、`fixtures/` 等目录）或 ≥2 个独立信号下标记 `suppressed`，并以 SARIF
   suppression 对象保留（带理由），而不是静默丢弃——召回审计与基线 un-suppress 都可行。
4. **example/placeholder 任何位置都不阻断**，只以 note/warning 级别保留在 T+1 清单里。
5. **单信号保护**：只有一个弱信号（例如文件叫 `_test.go` 但包路径正常）时不抑制，
   避免边界场景误杀。

这样压误报的杠杆全部作用在「弱证据 + 强夹具上下文」的交集上，真密钥（必有结构证据或
足够熵）的召回不受影响。

## 7. SARIF 与 CI 阻断

- 输出 SARIF v2.1.0：ruleId 带载体（`credscan/go-const`、`credscan/yaml` …）、
  `partialFingerprints` 支持基线 diff、`codeFlows` 展示传播链、properties 暴露
  证据/校验位/熵/构建标签/生成标记/夹具信号/suppression 理由。
- CI（`.github/workflows/credscan.yml`）：全量扫描产出 SARIF 并上传；PR 上额外跑
  `--incremental`（git diff 文件过滤）；评测门槛（单测 + 50 样本召回/FPR）同 job 执行。
- 阻断语义：仅未抑制的 `real` 使进程退出码为 1；example/placeholder/suppressed 不阻断。

## 8. 指标与性能

- **功能指标**（`eval/evaluate.py`，50 条标注样本）：召回 ≥85%、误报率 ≤15%，
  另含夹具抑制正确率与 SARIF 良构校验。
- **性能指标**（`eval/perf.py`）：约 20 万行合成仓库全量 <180s；单文件增量 <15s。
  增量模式只解析 diff 文件；Go 解析为每文件一次 CST 构建 + 线性遍历，符号表与折叠
  均为包内 O(n)，无跨文件二次遍历。
- 所有合成密钥由 `eval/synthetic.py`/`eval/builder.py` 用固定种子本地生成，
  AWS 风格 id 构造时即满足校验位，仓库内不含任何真实凭证。

## 9. 已知边界（诚实声明）

- 过程间污点只覆盖跨包常量/变量符号解析，不做函数返回值的跨过程污点（保守地视为
  未污染），后续可接 SSA。
- YAML parser 覆盖常用子集（缩进 map/seq、块标量、引号、注释），anchor/alias 与
  多文档流的复杂特性未全覆盖。
- 云厂商签名表按事件涉及厂商内置，新增厂商只需在 `_SIGNATURES` 增加结构化条目，
  不需要改解析框架。
