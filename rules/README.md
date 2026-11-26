# 规则例外与白名单维护

本目录中的例外文件有不同的所有权和作用范围，不得混为一谈。

## 项目自有 DNS 白名单

- `white.txt` 是本项目独立维护的 DNS 白名单。
- 只有经核实的正常业务误拦截才可加入；证据不足时保留待核查，不预先放行。
- 新增条目时，在域名附近记录可核查的证据链接或脱敏日志摘要、受影响应用/客户端及版本、复现条件、核实日期和精确放行范围。
- 优先放行精确主机名。除非证据证明整个注册域都需要放行，否则不要添加根域或宽泛通配范围。
- 不要在注释中记录反馈者的个人信息、令牌、Cookie、完整私人日志或其他敏感数据。

建议条目格式：

```text
# Evidence: <public issue / official documentation / redacted reproducible evidence>
# Affected: <application or site; client and version>
# Reproduction: <short reproducible scenario>
# Reviewed: YYYY-MM-DD
# Scope: exact hostname; reason for the narrow scope
host.example
```

如果某项信息不适用，应明确写明原因；不得编造证据、日期或测试结果。历史条目保留原有来源注释，不应为了符合新模板而补写未经核实的资料。

## 上游自带放行规则

上游过滤源中的例外规则由对应上游维护者提供，保存在构建时的上游源快照中，并由解析器按其规则语义处理。它们代表上游维护者的判断，不代表本项目已独立核实或背书。

不要把上游例外批量复制到 `white.txt`。需要区分来源时，应检查对应上游源、快照和审计报告；本项目自有白名单只记录本项目独立审核后决定的放行项。

## 浏览器规则排除项

`filter-exclude.txt` 用于排除经过单独审核的浏览器过滤规则，不是 DNS 白名单。条目应保持精确，并避免因排除整站规则而误删同一主机上的路径级广告规则。
