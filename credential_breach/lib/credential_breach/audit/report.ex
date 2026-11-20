defmodule CredentialBreach.Audit.Report do
  @moduledoc """
  影响面报告生成器。

  给定一份 `Dataset` 与泄露的访问密钥 ID，输出完整的取证报告：
  按密钥过滤全部调用、识别吊销事件、还原杀伤链时间线，并分别汇总
  被读取/下载的数据、新建身份与密钥、各类后门改动和被删改的资源。
  """

  alias CredentialBreach.Audit.{Dataset, Event, Meta}

  defstruct [
    :leaked_key,
    :leaked_user,
    :leaked_arn,
    :dataset,
    :revoked_at,
    :revoked_by,
    :window_seconds,
    total_events: 0,
    success_events: 0,
    denied_events: 0,
    sensitive_count: 0,
    critical_count: 0,
    events: [],
    first_seen_at: nil,
    last_seen_at: nil,
    stage_groups: [],
    data_accesses: [],
    data_total_bytes: 0,
    new_identities: [],
    backdoors: [],
    network_changes: [],
    evasions: [],
    destructions: [],
    ip_summary: [],
    user_agents: []
  ]

  @type t :: %__MODULE__{}

  # ------------------------------------------------------------------
  # 入口
  # ------------------------------------------------------------------

  @doc "基于数据集与泄露密钥 ID 构建报告。"
  @spec build(Dataset.t(), String.t()) :: t()
  def build(%Dataset{} = dataset, leaked_key) when is_binary(leaked_key) do
    # 1) 在全量日志里找吊销事件（操作人是安全团队，密钥不同，必须在过滤前找）
    {revoked_at, revoked_by} = detect_revocation(dataset.events, leaked_key)

    # 2) 只保留泄露密钥产生的调用
    key_events =
      dataset.events
      |> Enum.filter(&(&1.access_key_id == leaked_key))
      |> Enum.map(&re_stage_after_revocation(&1, revoked_at))
      |> Enum.sort_by(& &1.event_time, DateTime)

    first = List.first(key_events)
    last = List.last(key_events)
    principal = first || %Event{}

    report = %__MODULE__{
      leaked_key: leaked_key,
      leaked_user: principal.user_name,
      leaked_arn: principal.arn,
      dataset: dataset,
      revoked_at: revoked_at,
      revoked_by: revoked_by,
      events: key_events,
      total_events: length(key_events),
      first_seen_at: first && first.event_time,
      last_seen_at: last && last.event_time
    }

    report
    |> put_window()
    |> put_counters()
    |> put_stage_groups()
    |> put_data_accesses()
    |> put_new_identities()
    |> put_backdoors()
    |> put_network_changes()
    |> put_evasions()
    |> put_destructions()
    |> put_origins()
  end

  # ------------------------------------------------------------------
  # 吊销检测 & 阶段修正
  # ------------------------------------------------------------------

  defp detect_revocation(events, leaked_key) do
    event =
      Enum.find(events, fn e ->
        e.event_name == "UpdateAccessKey" and
          e.request_params["accessKeyId"] == leaked_key and
          e.request_params["status"] == "Inactive"
      end)

    if event do
      actor = event.user_name || event.arn || "未知操作人"
      {event.event_time, "#{actor}（#{event.source_ip}）"}
    else
      {nil, nil}
    end
  end

  # 吊销之后的调用（含失败试探）统一归入阶段 7
  defp re_stage_after_revocation(%Event{} = event, nil), do: event

  defp re_stage_after_revocation(%Event{} = event, %DateTime{} = revoked_at) do
    if DateTime.compare(event.event_time, revoked_at) == :gt do
      %{event | stage: 7}
    else
      event
    end
  end

  # ------------------------------------------------------------------
  # 汇总
  # ------------------------------------------------------------------

  defp put_window(%__MODULE__{first_seen_at: nil} = report), do: report

  defp put_window(report) do
    %{report | window_seconds: DateTime.diff(report.last_seen_at, report.first_seen_at)}
  end

  defp put_counters(report) do
    events = report.events

    %{
      report
      | success_events: Enum.count(events, & &1.success),
        denied_events: Enum.count(events, &(&1.category == :denied)),
        sensitive_count: Enum.count(events, & &1.sensitive),
        critical_count: Enum.count(events, &(&1.severity == :critical))
    }
  end

  defp put_stage_groups(report) do
    groups =
      report.events
      |> Enum.group_by(& &1.stage)
      |> Enum.sort_by(fn {stage, _} -> stage end)
      |> Enum.map(fn {stage, events} ->
        meta = Meta.stage(stage)

        %{
          stage: stage,
          name: meta.name,
          desc: meta.desc,
          badge: meta.badge,
          dot: meta.dot,
          started_at: List.first(events).event_time,
          ended_at: List.last(events).event_time,
          events: events,
          count: length(events),
          narrative: narrative(stage, events, report)
        }
      end)

    %{report | stage_groups: groups}
  end

  defp put_data_accesses(report) do
    accesses =
      report.events
      |> Enum.filter(
        &(&1.category in [:data_access, :data_export, :credential_harvest] and &1.success)
      )
      |> Enum.map(fn e ->
        %{
          event: e,
          kind: data_kind(e),
          target: data_target(e),
          bytes: e.bytes_out || 0,
          sensitive: e.sensitive
        }
      end)

    %{
      report
      | data_accesses: accesses,
        data_total_bytes: Enum.reduce(accesses, 0, &(&1.bytes + &2))
    }
  end

  defp put_new_identities(report) do
    # 影响面只统计成功落地的身份改动；吊销后的失败尝试留在原始事件与阶段 7，不计入清单。
    created_users =
      report.events
      |> Enum.filter(&(&1.event_name == "CreateUser" and &1.success))
      |> Enum.map(& &1.request_params["userName"])

    access_key_events =
      Enum.filter(report.events, &(&1.event_name == "CreateAccessKey" and &1.success))

    keyed_users =
      access_key_events
      |> Enum.map(& &1.request_params["userName"])
      |> Enum.uniq()

    rows =
      Enum.uniq(created_users ++ keyed_users)
      |> Enum.map(fn user ->
        keys =
          access_key_events
          |> Enum.filter(&(&1.request_params["userName"] == user))
          |> Enum.map(fn e ->
            get_in(e.response_elements || %{}, ["accessKey", "accessKeyId"]) || "（响应未返回 Key ID）"
          end)

        login? =
          Enum.any?(report.events, fn e ->
            e.event_name == "CreateLoginProfile" and e.request_params["userName"] == user
          end)

        admin? =
          Enum.any?(report.events, fn e ->
            e.event_name in ["AttachUserPolicy", "PutUserPolicy"] and
              e.request_params["userName"] == user and
              (String.contains?(e.request_params["policyArn"] || "", "AdministratorAccess") or
                 String.contains?(e.request_params["policyDocument"] || "", "*"))
          end)

        created_at =
          report.events
          |> Enum.find(fn e ->
            e.event_name == "CreateUser" and e.request_params["userName"] == user
          end)
          |> case do
            nil -> nil
            e -> e.event_time
          end

        %{
          user_name: user,
          newly_created?: user in created_users,
          access_keys: keys,
          console_login?: login?,
          admin?: admin?,
          created_at: created_at
        }
      end)

    # 后门角色单独附加在尾部字段里（UI 与 IAM 用户分开展示）
    roles =
      report.events
      |> Enum.filter(&(&1.event_name in ["CreateRole", "CreateInstanceProfile"]))
      |> Enum.map(fn e ->
        %{
          name: e.request_params["roleName"] || e.request_params["instanceProfileName"] || "-",
          kind: e.event_name,
          created_at: e.event_time,
          open_assume?:
            String.contains?(e.request_params["assumeRolePolicyDocument"] || "", "\"AWS\":\"*\"")
        }
      end)

    %{report | new_identities: %{users: rows, roles: roles}}
  end

  defp put_backdoors(report) do
    backdoors =
      report.events
      |> Enum.filter(&(&1.category in [:backdoor_permission]))
      |> Enum.map(fn e ->
        %{
          event: e,
          kind: backdoor_kind(e),
          target: backdoor_target(e),
          detail: e.summary
        }
      end)

    %{report | backdoors: backdoors}
  end

  defp put_network_changes(report) do
    changes =
      report.events
      |> Enum.filter(&(&1.category == :backdoor_network))
      |> Enum.map(fn e ->
        perms = e.request_params["ipPermissions"] || []

        ports =
          perms
          |> Enum.flat_map(fn p ->
            cidrs = Enum.map(p["ipRanges"] || [], & &1["cidrIp"])
            Enum.map(cidrs, fn cidr -> %{port: "#{p["fromPort"]}", cidr: cidr} end)
          end)

        %{
          event: e,
          security_group: e.request_params["groupId"],
          rules: ports
        }
      end)

    %{report | network_changes: changes}
  end

  defp put_evasions(report) do
    evasions =
      report.events
      |> Enum.filter(&(&1.category == :defense_evasion))
      |> Enum.map(fn e -> %{event: e, title: e.title, detail: e.summary} end)

    %{report | evasions: evasions}
  end

  defp put_destructions(report) do
    destructions =
      report.events
      |> Enum.filter(&(&1.category == :destruction))
      |> Enum.map(fn e ->
        %{
          event: e,
          resource: destruction_target(e),
          action: e.event_name,
          detail: e.summary
        }
      end)

    %{report | destructions: destructions}
  end

  defp put_origins(report) do
    ip_summary =
      report.events
      |> Enum.group_by(& &1.source_ip)
      |> Enum.map(fn {ip, events} ->
        label = Meta.ip_label(ip)

        %{
          ip: ip,
          label: label.label,
          note: label.note,
          count: length(events),
          first_seen: List.first(events).event_time,
          last_seen: List.last(events).event_time,
          categories: events |> Enum.map(& &1.category) |> Enum.uniq()
        }
      end)
      |> Enum.sort_by(& &1.count, :desc)

    user_agents =
      report.events
      |> Enum.group_by(& &1.user_agent)
      |> Enum.map(fn {ua, events} ->
        %{
          user_agent: ua,
          fingerprint: ua_fingerprint(ua),
          count: length(events),
          first_seen: List.first(events).event_time
        }
      end)
      |> Enum.sort_by(& &1.count, :desc)

    %{report | ip_summary: ip_summary, user_agents: user_agents}
  end

  # ------------------------------------------------------------------
  # 叙事文案
  # ------------------------------------------------------------------

  defp narrative(1, events, report) do
    e = List.first(events)

    "密钥首次被使用即调用 STS GetCallerIdentity，从 #{e.source_ip} 确认了身份 " <>
      "#{report.leaked_arn}。这一步说明攻击者拿到密钥后先验证可用性、确认所属账号与权限主体，" <>
      "是典型的武器化验证动作。"
  end

  defp narrative(2, events, _report) do
    services =
      events
      |> Enum.map(& &1.event_source)
      |> Enum.frequencies()
      |> Enum.map(fn {k, v} -> "#{k}(#{v})" end)
      |> Enum.join("、")

    denied = Enum.count(events, &(&1.category == :denied))

    "攻击者对 IAM、S3、EC2、RDS、CloudTrail 等服务发起 #{length(events)} 次枚举调用（#{services}），" <>
      "完整绘制账号内的身份、权限与数据资产地图；其中 #{denied} 次调用被权限策略拒绝，" <>
      "说明攻击者在试探该密钥的能力边界。"
  end

  defp narrative(3, events, report) do
    objs = Enum.count(events, &(&1.category == :data_access))
    exports = Enum.count(events, &(&1.category == :data_export))
    sensitive = Enum.count(events, & &1.sensitive)

    "本阶段共下载 #{objs} 个对象、发起 #{exports} 次数据库快照导出，外传数据约 " <>
      "#{format_bytes(report.data_total_bytes)}，其中 #{sensitive} 次命中敏感数据标记" <>
      "（客户 PII、薪资期权、生产环境变量、源代码备份等）。攻击者还在应用日志组中用 " <>
      "password/token/secret 等关键词过滤检索，试图翻找更多凭证。"
  end

  defp narrative(4, events, _report) do
    users =
      events
      |> Enum.filter(&(&1.event_name == "CreateUser"))
      |> Enum.map(& &1.request_params["userName"])
      |> Enum.join("、")

    "攻击者转入持久化阶段：创建后门 IAM 用户 #{users}，为其签发长期访问密钥、开启控制台密码登录" <>
      "并直接附加 AdministratorAccess；同时新建信任策略为 Principal=* 的角色并授予全权，" <>
      "开放安全组 22/6379 端口到 0.0.0.0/0，还给两个 S3 桶写入外部账号 711844205633 的跨账号读取策略，" <>
      "形成身份、权限、网络、存储四条并行的持久化通道。"
  end

  defp narrative(5, events, _report) do
    names =
      events
      |> Enum.map(& &1.request_params["name"])
      |> Enum.reject(&is_nil/1)
      |> Enum.uniq()
      |> Enum.join("、")

    "在持续操作前，攻击者先对审计设施下手：停止跟踪 #{names}、把日志投递桶改写到自己控制的 " <>
      "attacker-tmp-bucket-9x2k、关闭全局服务事件记录，最后直接删除跟踪。" <>
      "这意味着该时间点之后的操作在原账号内已无原生审计可查，本报告后续事件来自停止前的最后窗口与外部留痕。"
  end

  defp narrative(6, events, _report) do
    "攻击者进行破坏性清除：批量删除 S3 中的夜间数据库备份（5 个快照对象）、删除 RDS 手动快照、" <>
      "强制停止生产 EC2 实例并篡改其 userData 植入 C2 回连脚本（#{length(events)} 个动作），" <>
      "同时削弱受害方的数据恢复能力与服务可用性。"
  end

  defp narrative(7, events, %{revoked_at: revoked_at}) do
    "密钥已于 #{fmt(revoked_at)} 被安全团队置为 Inactive。此后攻击者仍从原攻击机发起 " <>
      "#{length(events)} 次调用，全部因 InvalidSecurityToken / AccessDenied 失败，" <>
      "甚至尝试重新创建访问密钥。失败仍在继续说明：攻击者并未放弃，且其此前种下的后门身份与跨账号授权" <>
      "可能仍然有效，必须按未闭环事件处置。"
  end

  # ------------------------------------------------------------------
  # 展示辅助
  # ------------------------------------------------------------------

  defp data_kind(%Event{category: :data_export}), do: "数据库快照导出"
  defp data_kind(%Event{category: :credential_harvest}), do: "日志凭证检索"
  defp data_kind(_), do: "对象下载"

  defp data_target(%Event{category: :data_access} = e) do
    "s3://#{e.request_params["bucketName"] || "-"}/#{e.request_params["key"] || "-"}"
  end

  defp data_target(%Event{category: :data_export} = e) do
    "快照 #{e.request_params["sourceArn"] || "-"} → s3://#{e.request_params["s3BucketName"]}/#{e.request_params["s3Prefix"] || ""}"
  end

  defp data_target(e),
    do: "#{e.event_source}:#{e.event_name} #{e.request_params["logGroupName"] || ""}"

  defp backdoor_kind(%Event{event_source: "s3"}), do: "存储桶策略后门"
  defp backdoor_kind(%Event{event_name: "ModifyInstanceAttribute"}), do: "实例 userData 植入"

  defp backdoor_kind(%Event{event_source: "iam", event_name: name}) do
    if String.starts_with?(name, "Attach"), do: "策略附加提权", else: "内联全权策略"
  end

  defp backdoor_kind(_), do: "权限变更"

  defp backdoor_target(%Event{event_source: "s3"} = e), do: "桶 #{e.request_params["bucketName"]}"

  defp backdoor_target(e),
    do:
      e.request_params["roleName"] || e.request_params["userName"] ||
        e.request_params["instanceId"] || "-"

  defp destruction_target(e) do
    cond do
      e.request_params["key"] ->
        "s3://#{e.request_params["bucketName"]}/#{e.request_params["key"]}"

      e.request_params["delete"] ->
        "桶 #{e.request_params["bucketName"]} 内多对象"

      e.request_params["dbSnapshotIdentifier"] ->
        "RDS 快照 #{e.request_params["dbSnapshotIdentifier"]}"

      e.request_params["instancesSet"] ->
        "EC2 实例 #{parse_instance_ids(e)}"

      true ->
        "#{e.event_source}:#{e.event_name}"
    end
  end

  defp parse_instance_ids(e) do
    # 括号不可省：管道优先级高于 ||，否则会被解析成 x || ([] |> ...)，
    # 在 x 非空时整段管道被跳过、直接返回原始 list。
    (e.request_params["instancesSet"] || [])
    |> Enum.map(& &1["instanceId"])
    |> Enum.join(", ")
  end

  defp ua_fingerprint(ua) do
    cond do
      String.contains?(ua, "aws-cli") -> "AWS CLI 命令行"
      String.contains?(ua, "jenkins") -> "Jenkins SDK（正常 CI）"
      String.contains?(ua, "Mozilla") -> "浏览器控制台"
      String.contains?(ua, "ruby") -> "Ruby SDK"
      true -> "未知工具"
    end
  end

  defp format_bytes(n) when n >= 1_073_741_824, do: "#{Float.round(n / 1_073_741_824, 2)} GB"
  defp format_bytes(n) when n >= 1_048_576, do: "#{Float.round(n / 1_048_576, 1)} MB"
  defp format_bytes(n) when n >= 1024, do: "#{div(n, 1024)} KB"
  defp format_bytes(n), do: "#{n} B"

  defp fmt(%DateTime{} = dt), do: Calendar.strftime(dt, "%m-%d %H:%M:%S UTC")
  defp fmt(_), do: "未知时间"
end
