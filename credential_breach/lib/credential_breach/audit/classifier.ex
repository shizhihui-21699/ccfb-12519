defmodule CredentialBreach.Audit.Classifier do
  @moduledoc """
  对归一化审计事件做取证分类：

    * `category` —— 事件性质（侦察 / 数据访问 / 后门 / 规避 / 破坏 / 被拒 …）
    * `stage`   —— 攻击者杀伤链阶段（1-7），用于还原操作经过
    * `severity`—— 严重级别，驱动 UI 配色
    * `title` / `summary` —— 面向调查员的中文动作描述

  分类只依赖单条事件自身字段；需要全局上下文（如吊销时间）的调整在
  `CredentialBreach.Audit.Report` 中完成。
  """

  alias CredentialBreach.Audit.Event

  # 命中即视为敏感数据的关键词（对象键 / 桶名 / 日志过滤表达式）
  @sensitive_keywords ~w(pii 薪资 期权 .env secret password token 合同 尽调 customer payroll 身份证)

  @doc """
  填充事件的分类字段并返回。
  """
  def classify(%Event{} = event) do
    event
    |> classify_base()
    |> mark_sensitive()
    |> describe()
  end

  # ---------- 类别与阶段 ----------

  defp classify_base(%Event{error_code: code} = event) when is_binary(code) do
    %{event | category: :denied, stage: 2, severity: :low}
  end

  defp classify_base(%Event{event_name: "GetCallerIdentity"} = event) do
    %{event | category: :recon, stage: 1, severity: :low}
  end

  # 审计规避
  defp classify_base(%Event{event_source: "cloudtrail", event_name: name} = event)
       when name in ["StopLogging", "UpdateTrail", "DeleteTrail", "StopImport"] do
    %{event | category: :defense_evasion, stage: 5, severity: :critical}
  end

  # 数据读取 / 下载
  defp classify_base(%Event{event_source: "s3", event_name: "GetObject"} = event) do
    %{event | category: :data_access, stage: 3, severity: :medium}
  end

  # 日志里翻凭证
  defp classify_base(%Event{event_source: "logs", event_name: name} = event)
       when name in ["FilterLogEvents", "GetLogEvents", "StartQuery", "GetQueryResults"] do
    %{event | category: :credential_harvest, stage: 3, severity: :high}
  end

  # 数据库快照导出
  defp classify_base(%Event{event_source: "rds", event_name: "StartExportTask"} = event) do
    %{event | category: :data_export, stage: 3, severity: :high}
  end

  # 后门 —— 身份
  defp classify_base(%Event{event_source: "iam", event_name: name} = event)
       when name in [
              "CreateUser",
              "CreateAccessKey",
              "CreateLoginProfile",
              "CreateServiceSpecificCredential",
              "CreateRole",
              "CreateInstanceProfile"
            ] do
    %{event | category: :backdoor_identity, stage: 4, severity: :critical}
  end

  # 后门 —— 权限
  defp classify_base(%Event{event_source: "iam", event_name: name} = event)
       when name in [
              "AttachUserPolicy",
              "AttachRolePolicy",
              "AttachGroupPolicy",
              "PutUserPolicy",
              "PutRolePolicy",
              "PutGroupPolicy",
              "CreatePolicy",
              "UpdateAccountPasswordPolicy",
              "UpdateAssumeRolePolicy"
            ] do
    %{event | category: :backdoor_permission, stage: 4, severity: :high}
  end

  # 后门 —— 网络
  defp classify_base(
         %Event{event_source: "ec2", event_name: "AuthorizeSecurityGroupIngress"} = event
       ) do
    %{event | category: :backdoor_network, stage: 4, severity: :high}
  end

  # 后门 —— 存储桶策略 / ACL
  defp classify_base(%Event{event_source: "s3", event_name: name} = event)
       when name in ["PutBucketPolicy", "PutBucketAcl", "PutPublicAccessBlock"] do
    %{event | category: :backdoor_permission, stage: 4, severity: :high}
  end

  # 后门 —— 实例用户数据植入
  defp classify_base(%Event{event_source: "ec2", event_name: "ModifyInstanceAttribute"} = event) do
    %{event | category: :backdoor_permission, stage: 4, severity: :critical}
  end

  # 破坏 / 清除
  defp classify_base(%Event{event_name: name} = event)
       when name in [
              "DeleteObject",
              "DeleteObjects",
              "DeleteBucket",
              "DeleteDBSnapshot",
              "DeleteDBInstance",
              "TerminateInstances",
              "StopInstances",
              "DeleteUser",
              "DeleteRole",
              "DeleteRolePolicy",
              "DeleteUserPolicy",
              "DeregisterImage"
            ] do
    %{event | category: :destruction, stage: 6, severity: :critical}
  end

  # 其余只读调用一律视为侦察
  defp classify_base(%Event{read_only: true} = event) do
    %{event | category: :recon, stage: 2, severity: :low}
  end

  defp classify_base(%Event{} = event) do
    %{event | category: :other, stage: 4, severity: :info}
  end

  # ---------- 敏感数据标记 ----------

  defp mark_sensitive(%Event{category: :data_access} = event) do
    haystack = "#{object_key(event)} #{bucket(event)}"
    %{event | sensitive: Enum.any?(@sensitive_keywords, &String.contains?(haystack, &1))}
  end

  defp mark_sensitive(%Event{event_source: "logs"} = event) do
    pattern = event.request_params["filterPattern"] || ""
    %{event | sensitive: String.contains?(pattern, ["password", "token", "secret"])}
  end

  defp mark_sensitive(event), do: event

  # ---------- 中文动作描述 ----------

  defp describe(%Event{} = event) do
    {title, summary} = describe_event(event)
    %{event | title: title, summary: summary}
  end

  defp describe_event(%Event{category: :denied, event_name: name} = event) do
    {"调用被拒绝：#{name}", "#{event.error_code} — #{truncate(event.error_message, 90)}"}
  end

  defp describe_event(%Event{event_name: "GetCallerIdentity"} = event) do
    {"验证泄露密钥有效性", "GetCallerIdentity 返回身份 #{event.arn}，攻击者确认密钥可用并摸清当前权限主体"}
  end

  defp describe_event(%Event{event_source: "s3", event_name: "GetObject"} = event) do
    {"下载对象 s3://#{bucket(event)}/#{object_key(event)}",
     "读取 #{format_bytes(event.bytes_out)}" <> sensitive_note(event)}
  end

  defp describe_event(%Event{event_name: "StartExportTask"} = event) do
    id = event.request_params["exportTaskIdentifier"] || "-"
    target = event.request_params["s3BucketName"] || "-"
    {"发起 RDS 快照导出任务 #{id}", "快照数据被导出到桶 #{target}，属变相整库窃取"}
  end

  defp describe_event(%Event{event_source: "logs", event_name: "FilterLogEvents"} = event) do
    group = event.request_params["logGroupName"] || "-"
    pattern = event.request_params["filterPattern"] || "-"
    {"在日志组 #{group} 中检索敏感词", "过滤表达式：#{pattern}，意图从应用日志中捞取凭证"}
  end

  defp describe_event(%Event{event_name: "CreateUser"} = event) do
    name = event.request_params["userName"] || "-"
    {"创建后门 IAM 用户 #{name}", "新用户 #{name} 被创建，标签伪装成 #{inspect_tags(event)}"}
  end

  defp describe_event(%Event{event_name: "CreateAccessKey"} = event) do
    target = event.request_params["userName"] || "-"
    key = get_in(event.response_elements || %{}, ["accessKey", "accessKeyId"]) || "（响应未记录）"
    {"为 #{target} 创建访问密钥 #{key}", "秘密密钥仅创建时返回一次，攻击者已取得长期可用凭证"}
  end

  defp describe_event(%Event{event_name: "CreateLoginProfile"} = event) do
    target = event.request_params["userName"] || "-"
    reset = event.request_params["passwordResetRequired"]
    {"为 #{target} 开启控制台登录", "且 passwordResetRequired=#{reset}，攻击者可直接用密码登录控制台"}
  end

  defp describe_event(%Event{event_name: "CreateRole"} = event) do
    role = event.request_params["roleName"] || "-"
    policy = event.request_params["assumeRolePolicyDocument"] || ""
    wildcard = String.contains?(policy, "\"AWS\":\"*\"")
    {"创建角色 #{role}", if(wildcard, do: "信任策略允许任意 AWS 账户（Principal=*）扮演，典型后门角色", else: "新建可扮演角色")}
  end

  defp describe_event(%Event{event_name: "AttachUserPolicy"} = event) do
    {"给用户 #{event.request_params["userName"]} 附加策略 #{policy_name(event)}", policy_warning(event)}
  end

  defp describe_event(%Event{event_name: "AttachRolePolicy"} = event) do
    {"给角色 #{event.request_params["roleName"]} 附加策略 #{policy_name(event)}", policy_warning(event)}
  end

  defp describe_event(%Event{event_name: "PutRolePolicy"} = event) do
    {"给角色 #{event.request_params["roleName"]} 写入内联策略 #{event.request_params["policyName"] || "-"}",
     policy_warning(event)}
  end

  defp describe_event(%Event{event_name: "AuthorizeSecurityGroupIngress"} = event) do
    sg = event.request_params["groupId"] || "-"
    {ports, cidrs} = parse_permissions(event)
    {"安全组 #{sg} 放行入站流量", "端口 #{ports} 对 #{cidrs} 开放，暴露 SSH/缓存等管理面"}
  end

  defp describe_event(%Event{event_source: "s3", event_name: "PutBucketPolicy"} = event) do
    bucket = event.request_params["bucketName"] || "-"
    policy = event.request_params["bucketPolicy"] || ""

    {cross, principal} =
      cond do
        String.contains?(policy, "\"AWS\":\"*\"") -> {true, "Principal=*（任意账户）"}
        String.contains?(policy, "arn:aws:iam::") -> {true, "外部账户 ARN"}
        true -> {false, "自定义主体"}
      end

    {"改写桶 #{bucket} 的访问策略",
     if(cross, do: "策略向 #{principal} 授权，属跨账号持久化后门", else: "桶访问策略被修改：#{principal}")}
  end

  defp describe_event(%Event{event_name: "ModifyInstanceAttribute"} = event) do
    instance = event.request_params["instanceId"] || "-"
    attr = event.request_params["attribute"] || "-"
    {"篡改实例 #{instance} 的 #{attr}", "用户数据中植入下载执行脚本，实例重启即回连攻击者 C2"}
  end

  defp describe_event(%Event{event_name: "StopLogging"} = event) do
    {"关闭 CloudTrail 跟踪 #{event.request_params["name"] || "-"}", "停止记录管理事件，后续操作失去审计痕迹"}
  end

  defp describe_event(%Event{event_name: "UpdateTrail"} = event) do
    name = event.request_params["name"] || "-"
    bucket = event.request_params["s3BucketName"] || "-"
    {"篡改 CloudTrail 跟踪 #{name}", "日志投递目标被改为 #{bucket}，并关闭全局服务事件记录"}
  end

  defp describe_event(%Event{event_name: "DeleteTrail"} = event) do
    {"删除 CloudTrail 跟踪 #{event.request_params["name"] || "-"}", "审计设施被彻底移除"}
  end

  defp describe_event(%Event{event_name: "DeleteObject"} = event) do
    {"删除对象 s3://#{event.request_params["bucketName"] || "-"}/#{event.request_params["key"] || "-"}",
     "备份/数据文件被删除，削弱恢复能力"}
  end

  defp describe_event(%Event{event_name: "DeleteObjects"} = event) do
    bucket = event.request_params["bucketName"] || "-"
    count = get_in(event.request_params, ["delete", "objects"]) |> safe_count()
    {"批量删除桶 #{bucket} 中的 #{count} 个对象", "多份夜间备份快照被一次性清除"}
  end

  defp describe_event(%Event{event_name: "DeleteDBSnapshot"} = event) do
    {"删除 RDS 快照 #{event.request_params["dbSnapshotIdentifier"] || "-"}", "数据库时间点恢复能力被破坏"}
  end

  defp describe_event(%Event{event_name: "StopInstances"} = event) do
    ids = parse_instances(event)
    {"强制停止实例 #{ids}", "生产实例被关停，结合用户数据篡改形成中断+植入双重影响"}
  end

  # 通用侦察
  defp describe_event(%Event{category: :recon} = event) do
    {"侦察：#{event.event_name}", recon_detail(event)}
  end

  defp describe_event(%Event{} = event) do
    {event.event_name, "对 #{event.event_source} 服务发起调用"}
  end

  # ---------- 小工具 ----------

  defp bucket(event),
    do: event.request_params["bucketName"] || event.request_params["bucket"] || "-"

  defp object_key(event), do: event.request_params["key"] || event.request_params["prefix"] || "-"

  defp sensitive_note(%Event{sensitive: true}), do: "，命中敏感数据标记（PII/凭证/机密文件）"
  defp sensitive_note(_), do: ""

  defp policy_name(event) do
    event.request_params["policyArn"]
    |> Kernel.||("")
    |> String.split("/")
    |> List.last()
    |> Kernel.||(event.request_params["policyName"] || "-")
  end

  defp policy_warning(event) do
    arn = event.request_params["policyArn"] || ""
    doc = event.request_params["policyDocument"] || ""

    cond do
      String.contains?(arn, "AdministratorAccess") ->
        "直接授予 AdministratorAccess 管理员权限，权限提升到账号级"

      String.contains?(doc, "\"Action\":\"*\"") or String.contains?(doc, "\"Action\": \"*\"") ->
        "内联策略允许 Action:*，等同于管理员权限"

      true ->
        "附加 IAM 策略，扩大可调用的 API 范围"
    end
  end

  defp inspect_tags(event) do
    tags = event.request_params["tags"] || []
    inspect(tags, limit: 60)
  end

  defp parse_permissions(event) do
    perms = event.request_params["ipPermissions"] || []

    ports =
      perms
      |> Enum.map(fn p ->
        if p["fromPort"] == p["toPort"],
          do: "#{p["fromPort"]}",
          else: "#{p["fromPort"]}-#{p["toPort"]}"
      end)
      |> Enum.join(", ")
      |> case do
        "" -> "-"
        str -> str
      end

    cidrs =
      perms
      |> Enum.flat_map(fn p -> Enum.map(p["ipRanges"] || [], & &1["cidrIp"]) end)
      |> Enum.join(", ")
      |> case do
        "" -> "-"
        str -> str
      end

    {ports, cidrs}
  end

  defp parse_instances(event) do
    event.request_params
    |> get_in(["instancesSet"])
    |> Kernel.||([])
    |> Enum.map(& &1["instanceId"])
    |> Enum.join(", ")
    |> case do
      "" -> "-"
      str -> str
    end
  end

  defp recon_detail(event) do
    target =
      event.request_params
      |> Enum.reject(fn {k, _} -> k in ["maxResults", "startTime"] end)
      |> Enum.map(fn {k, v} -> "#{k}=#{truncate(to_string_safe(v), 40)}" end)
      |> Enum.join("，")

    if target == "", do: "枚举 #{event.event_source} 服务资源", else: "请求参数：#{target}"
  end

  defp safe_count(nil), do: 0
  defp safe_count(list) when is_list(list), do: length(list)
  defp safe_count(_), do: "?"

  defp to_string_safe(v) when is_binary(v), do: v
  defp to_string_safe(v), do: inspect(v, limit: 50)

  defp truncate(nil, _len), do: ""
  defp truncate(str, len) when byte_size(str) <= len, do: str
  defp truncate(str, len), do: binary_part(str, 0, len) <> "…"

  defp format_bytes(nil), do: "未知大小数据"

  defp format_bytes(n) when n >= 1_073_741_824 do
    "#{Float.round(n / 1_073_741_824, 2)} GB"
  end

  defp format_bytes(n) when n >= 1_048_576 do
    "#{Float.round(n / 1_048_576, 1)} MB"
  end

  defp format_bytes(n) when n >= 1024, do: "#{div(n, 1024)} KB"
  defp format_bytes(n), do: "#{n} B"
end
