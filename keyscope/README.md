# Keyscope — 泄露密钥影响面调查台

开发把云平台访问密钥贴进了公开代码片段,三天后才发现。密钥已经吊销,但这三天里对方拿它干了什么?
Keyscope 回答这个问题:导入云操作审计日志,按泄露的 Access Key ID 还原全部调用,给出影响面清单和攻击经过时间线。

## 启动

```bash
mix deps.get
mix phx.server
```

打开 http://localhost:4000 ,点击「加载样例日志」,然后对 `AKIA3X7KQZMWJPLM4V2T` 开始调查。

## 功能

- **导入**:粘贴 JSONL、上传文件,或加载内置样例。支持三种格式:每行一条事件的 JSONL、CloudTrail 批量格式 `{"Records":[...]}`、顶层 JSON 数组。
- **密钥索引**:导入后列出日志中出现的所有 Access Key ID、关联身份、调用次数与活动时间窗口。
- **影响面清单**(按类别归并):
  - 数据读取 / 下载(S3 对象、Secrets Manager、SSM 参数、DynamoDB 扫描、RDS 日志、KMS 解密……)
  - 新建账号 / 密钥 / 后门(IAM 用户、访问密钥、控制台密码、Lambda 函数、定时规则、安全组放行)
  - 权限提升(附加管理员策略、修改角色信任策略)
  - 防御规避 / 痕迹清理(停止 CloudTrail、删除告警与日志组)
  - 删除 / 篡改的资源
  - 资源滥用(盗开实例挖矿)
  - 侦察探测
- **攻击经过**:把所有调用按时间排序,相邻同类操作(30 分钟窗口内)合并为一个步骤,串成 侦察 → 提权 → 持久化 → 窃取 → 滥用 → 清痕 → 破坏 的完整叙事。
- **综合风险评级** 与处置建议。

## 样例日志

`priv/samples/cloudtrail_leak.jsonl` — 55 条模拟 CloudTrail 事件。剧情:开发 `chen.lei` 的密钥
`AKIA3X7KQZMWJPLM4V2T` 于 2026-11-17 泄露,攻击者(45.155.204.117 / 185.220.101.4,aws-cli 与 Boto3)
三天内完成侦察、读取密钥与 PII 数据、创建后门账号 `svc-backup-agent`(附管理员策略 + 控制台密码)、
修改角色信任策略允许外部账号扮演、盗开 4 台 g5.12xlarge、部署定时 Lambda 后门、停止日志与告警、
删除备份与快照,直到 11-20 密钥被吊销(后续调用返回 `InvalidAccessKeyId`)——但攻击者随即改用
后门密钥 `AKIA9X1KQZMWJBACKDOOR` 继续活动,这正是"只吊销泄露密钥不够"的直观演示。

日志中混入了其他用户(`wang.fang`、`cicd-deployer` 角色)的正常调用作为噪声,检验按密钥过滤的准确性。

## 测试

```bash
mix test
```

## 代码结构

```
lib/keyscope/audit/event.ex         # 事件结构体与解析
lib/keyscope/audit/loader.ex        # JSONL / Records / 数组三种格式导入
lib/keyscope/audit/investigator.ex  # 分类规则、影响面归并、时间线叙事
lib/keyscope/audit/store.ex         # 导入数据的内存存储(本地单用户)
lib/keyscope_web/controllers/investigation_controller.ex
lib/keyscope_web/controllers/investigation_html/  # 导入页与报告页模板
priv/samples/cloudtrail_leak.jsonl  # 模拟审计日志
```
