defmodule Keyscope.Audit.Investigator do
  @moduledoc """
  泄露密钥影响面分析:
    - 按 access_key_id 还原全部调用
    - 按类别归并:数据读取/下载、持久化后门、权限提升、防御规避、删除篡改、资源滥用、侦察
    - 将事件按时间串成攻击经过(阶段化时间线)
  """

  alias Keyscope.Audit.Event

  @categories [
    {:data_access, "数据读取 / 下载", "被读取或下载的数据,存在泄露风险", :high},
    {:persistence, "新建账号 / 密钥 / 后门", "攻击者留下的持久化通道,需全部清理", :critical},
    {:privilege_escalation, "权限提升", "扩大权限边界的操作", :critical},
    {:defense_evasion, "防御规避 / 痕迹清理", "针对日志、告警、监控的破坏", :critical},
    {:destructive, "删除 / 篡改的资源", "数据与资源遭到删除或修改", :high},
    {:resource_abuse, "资源滥用", "盗用算力等资源(挖矿、跳板)", :medium},
    {:recon, "侦察探测", "盘点环境的信息收集行为", :low},
    {:other, "其他调用", "未归类的调用", :info}
  ]

  def categories, do: @categories

  # ---------- 分类规则表 ----------

  @doc "对单条事件分类,返回 {category, severity, 一句话描述}"
  def classify(%Event{} = e) do
    svc = Event.service(e)
    name = e.event_name

    cond do
      not Event.success?(e) ->
        {:other, :info, "调用被拒绝或失败(#{e.error_code || "未知错误"})"}

      data_access?(svc, name) ->
        {:data_access, :high, describe_data_access(e)}

      persistence?(svc, name) ->
        {:persistence, :critical, describe_persistence(e)}

      privilege_escalation?(svc, name) ->
        {:privilege_escalation, :critical, describe_escalation(e)}

      defense_evasion?(svc, name) ->
        {:defense_evasion, :critical, describe_evasion(e)}

      destructive?(svc, name) ->
        {:destructive, :high, describe_destructive(e)}

      resource_abuse?(svc, name) ->
        {:resource_abuse, :medium, describe_abuse(e)}

      recon?(svc, name) ->
        {:recon, :low, "探测 #{svc} 服务的 #{name} 接口"}

      svc == "iam" and name == "UpdateAccessKey" ->
        status = (e.request_params || %{})["status"]
        {:other, :info, "变更访问密钥 #{((e.request_params || %{})["accessKeyId"]) || "?"} 状态为 #{status || "?"}"}

      true ->
        {:other, :info, "#{svc}:#{name}"}
    end
  end

  # --- 数据读取 / 下载 ---
  defp data_access?("s3", n), do: n in ~w(GetObject GetObjectTorrent SelectObjectContent GetObjectTagging CopyObject)
  defp data_access?("secretsmanager", n), do: n in ~w(GetSecretValue BatchGetSecretValue)
  defp data_access?("ssm", n), do: n in ~w(GetParameter GetParameters GetParametersByPath)
  defp data_access?("dynamodb", n), do: n in ~w(GetItem BatchGetItem Query Scan ExportTableToPointInTime)
  defp data_access?("rds", n), do: n in ~w(DownloadDBLogFilePortion DownloadCompleteDBLogFile)
  defp data_access?("logs", n), do: n in ~w(GetLogEvents FilterLogEvents StartQuery GetQueryResults)
  defp data_access?("lambda", n), do: n in ~w(GetFunction GetLayerVersion)
  defp data_access?("ecr", n), do: n in ~w(BatchGetImage GetDownloadUrlForLayer)
  defp data_access?("glacier", n), do: String.starts_with?(n, "Get") or n == "InitiateJob"
  defp data_access?("elasticfilesystem", n), do: n == "DescribeFileSystems"
  defp data_access?("kms", n), do: n in ~w(Decrypt GenerateDataKey)
  defp data_access?("rds-data", _), do: true
  defp data_access?("execute-api", _), do: true
  defp data_access?(_, _), do: false

  # --- 持久化后门 ---
  defp persistence?("iam", n) do
    n in ~w(CreateUser CreateAccessKey CreateLoginProfile UpdateLoginProfile CreateServiceSpecificCredential CreateVirtualMFADevice EnableMFADevice)
  end

  defp persistence?("lambda", n) do
    String.starts_with?(n, ["CreateFunction", "UpdateFunctionCode", "AddPermission", "CreateEventSourceMapping"])
  end
  defp persistence?("events", n), do: n in ~w(PutRule PutTargets)
  defp persistence?("ssm", n), do: n in ~w(SendCommand CreateAssociation)
  defp persistence?("ec2", n), do: n in ~w(AuthorizeSecurityGroupIngress CreateKeyPair ImportKeyPair)
  defp persistence?("organizations", n), do: n in ~w(CreateAccount InviteAccountToOrganization)
  defp persistence?(_, _), do: false

  # --- 权限提升 ---
  defp privilege_escalation?("iam", n) do
    n in ~w(AttachUserPolicy AttachRolePolicy AttachGroupPolicy PutUserPolicy PutRolePolicy PutGroupPolicy
            AddUserToGroup UpdateAssumeRolePolicy CreatePolicyVersion SetDefaultPolicyVersion PassRole)
  end

  defp privilege_escalation?("sts", n), do: n == "AssumeRole"
  defp privilege_escalation?(_, _), do: false

  # --- 防御规避 ---
  defp defense_evasion?("cloudtrail", n), do: n in ~w(StopLogging DeleteTrail UpdateTrail PutEventSelectors)
  defp defense_evasion?("guardduty", n), do: n in ~w(DeleteDetector StopMonitoringMembers UpdateDetector)
  defp defense_evasion?("config", n), do: n in ~w(StopConfigurationRecorder DeleteConfigurationRecorder DeleteDeliveryChannel)
  defp defense_evasion?("cloudwatch", n), do: n in ~w(DeleteAlarms DisableAlarmActions DeleteDashboards)
  defp defense_evasion?("logs", n), do: n in ~w(DeleteLogGroup DeleteLogStream)
  defp defense_evasion?("securityhub", n), do: String.starts_with?(n, "Disable") or String.starts_with?(n, "Delete")
  defp defense_evasion?(_, _), do: false

  # --- 删除 / 篡改 ---
  defp destructive?(svc, n) do
    String.starts_with?(n, "Delete") or String.starts_with?(n, "Terminate") or
      String.starts_with?(n, "Remove") or n in ~w(DeregisterAmi StopInstances RebootInstances) or
      (svc == "s3" and n in ~w(PutBucketPolicy PutBucketAcl PutObjectAcl PutLifecycleConfiguration)) or
      (svc == "rds" and n in ~w(ModifyDBInstance ModifyDBCluster)) or
      (svc == "dynamodb" and n in ~w(PutItem UpdateItem DeleteItem))
  end

  # --- 资源滥用 ---
  defp resource_abuse?("ec2", n), do: n in ~w(RunInstances RequestSpotInstances)
  defp resource_abuse?("lightsail", n), do: String.starts_with?(n, "Create")
  defp resource_abuse?("sagemaker", n), do: String.starts_with?(n, "Create")
  defp resource_abuse?("batch", n), do: n in ~w(SubmitJob CreateComputeEnvironment)
  defp resource_abuse?(_, _), do: false

  # --- 侦察 ---
  defp recon?(_svc, n) do
    String.starts_with?(n, "List") or String.starts_with?(n, "Describe") or
      String.starts_with?(n, "Get") or String.starts_with?(n, "Lookup") or
      n in ~w(GetCallerIdentity HeadBucket Search)
  end

  # ---------- 描述生成 ----------

  defp describe_data_access(%Event{} = e) do
    svc = Event.service(e)
    p = e.request_params || %{}

    case svc do
      "s3" ->
        bucket = p["bucketName"] || p["bucket"] || "?"
        key = p["key"] || p["objectKey"]
        if key, do: "下载对象 s3://#{bucket}/#{key}", else: "读取存储桶 s3://#{bucket}"

      "secretsmanager" ->
        "读取密钥 #{p["secretId"] || p["secretName"] || "?"}"

      "ssm" ->
        "读取参数 #{p["name"] || inspect(p["names"]) || "?"}"

      "dynamodb" ->
        "#{e.event_name} 表 #{p["tableName"] || "?"}"

      "rds" ->
        "下载数据库日志 #{p["dbInstanceIdentifier"] || "?"}"

      "logs" ->
        "读取日志组 #{p["logGroupName"] || "?"}"

      "kms" ->
        "使用 KMS #{e.event_name}(可能用于解密敏感数据)"

      "lambda" ->
        "获取函数代码/配置 #{p["functionName"] || "?"}"

      _ ->
        "#{svc}:#{e.event_name}"
    end
  end

  defp describe_persistence(%Event{} = e) do
    p = e.request_params || %{}
    resp = e.response_elements || %{}

    case {Event.service(e), e.event_name} do
      {"iam", "CreateUser"} ->
        "创建 IAM 用户 #{p["userName"] || "?"}"

      {"iam", "CreateAccessKey"} ->
        key = get_in(resp, ["accessKey", "accessKeyId"]) || "新密钥"
        "为用户 #{p["userName"] || "?"} 创建访问密钥 #{key}"

      {"iam", "CreateLoginProfile"} ->
        "为用户 #{p["userName"] || "?"} 设置控制台登录密码"

      {"lambda", n} ->
        if String.starts_with?(n, ["CreateFunction", "UpdateFunctionCode"]) do
          "部署/更新 Lambda 函数 #{p["functionName"] || "?"}(可植入定时执行的恶意代码)"
        else
          "lambda:#{n}"
        end

      {"ec2", "AuthorizeSecurityGroupIngress"} ->
        "放行安全组入站规则(可能打开远程访问通道)"

      {"ec2", n} when n in ["CreateKeyPair", "ImportKeyPair"] ->
        "创建/导入 EC2 密钥对 #{p["keyName"] || "?"}"

      {svc, n} ->
        "#{svc}:#{n}"
    end
  end

  defp describe_escalation(%Event{} = e) do
    p = e.request_params || %{}

    case e.event_name do
      n when n in ["AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy"] ->
        target = p["userName"] || p["roleName"] || p["groupName"] || "?"
        "为 #{target} 附加策略 #{p["policyArn"] || "?"}"

      n when n in ["PutUserPolicy", "PutRolePolicy", "PutGroupPolicy"] ->
        target = p["userName"] || p["roleName"] || p["groupName"] || "?"
        "为 #{target} 写入内联策略 #{p["policyName"] || "?"}"

      "UpdateAssumeRolePolicy" ->
        "修改角色 #{p["roleName"] || "?"} 的信任策略(允许外部主体扮演)"

      "AssumeRole" ->
        "扮演角色 #{p["roleArn"] || "?"}"

      _ ->
        "iam:#{e.event_name}"
    end
  end

  defp describe_evasion(%Event{} = e) do
    p = e.request_params || %{}

    case e.event_name do
      "StopLogging" -> "停止 CloudTrail 日志记录 #{p["name"] || ""}"
      "DeleteTrail" -> "删除 CloudTrail 跟踪 #{p["name"] || ""}"
      "UpdateTrail" -> "修改 CloudTrail 跟踪配置 #{p["name"] || ""}"
      "DeleteAlarms" -> "删除 CloudWatch 告警 #{inspect(p["alarmNames"] || "?")}"
      "DeleteLogGroup" -> "删除日志组 #{p["logGroupName"] || "?"}"
      "DeleteDetector" -> "删除 GuardDuty 检测器"
      n -> "防御规避:#{n}"
    end
  end

  defp describe_destructive(%Event{} = e) do
    svc = Event.service(e)
    p = e.request_params || %{}

    case {svc, e.event_name} do
      {"s3", "DeleteObject"} -> "删除对象 s3://#{p["bucketName"] || "?"}/#{p["key"] || "?"}"
      {"s3", "DeleteObjects"} -> "批量删除 s3://#{p["bucketName"] || "?"} 中对象"
      {"s3", "DeleteBucket"} -> "删除存储桶 s3://#{p["bucketName"] || "?"}"
      {"rds", "DeleteDBSnapshot"} -> "删除数据库快照 #{p["dbSnapshotIdentifier"] || "?"}"
      {"rds", "DeleteDBInstance"} -> "删除数据库实例 #{p["dbInstanceIdentifier"] || "?"}"
      {"dynamodb", "DeleteTable"} -> "删除表 #{p["tableName"] || "?"}"
      {"ec2", "TerminateInstances"} -> "销毁实例 #{inspect(p["instancesSet"] || p["instanceIds"] || "?")}"
      {svc, n} -> "#{svc}:#{n}"
    end
  end

  defp describe_abuse(%Event{} = e) do
    p = e.request_params || %{}
    type = p["instanceType"] || "?"

    count =
      case get_in(p, ["instancesSet", "items"]) do
        [first | _] when is_map(first) -> first["maxCount"] || first["minCount"] || 1
        _ -> p["maxCount"] || p["instanceCount"] || 1
      end

    "启动 #{count} 台 #{type} 实例(疑似挖矿/跳板)"
  end

  # ---------- 调查主流程 ----------

  @doc "对导入的事件按密钥做完整调查,返回报告 map。"
  def investigate(events, key_id) do
    matched =
      events
      |> Enum.filter(&(&1.access_key_id == key_id))
      |> Enum.sort_by(&(&1.event_time || ~U[1970-01-01 00:00:00Z]), DateTime)

    classified =
      Enum.map(matched, fn e ->
        {cat, sev, desc} = classify(e)
        %{event: e, category: cat, severity: sev, description: desc}
      end)

    %{
      key_id: key_id,
      total: length(classified),
      first_seen: first_time(matched),
      last_seen: last_time(matched),
      source_ips: matched |> Enum.map(& &1.source_ip) |> Enum.reject(&is_nil/1) |> Enum.uniq(),
      user_agents: matched |> Enum.map(& &1.user_agent) |> Enum.reject(&is_nil/1) |> Enum.uniq(),
      regions: matched |> Enum.map(& &1.region) |> Enum.reject(&is_nil/1) |> Enum.uniq(),
      principals: matched |> Enum.map(& &1.principal) |> Enum.uniq(),
      denied_count: Enum.count(matched, &(not Event.success?(&1))),
      by_category: group_by_category(classified),
      timeline: build_timeline(classified),
      risk: overall_risk(classified)
    }
  end

  defp first_time([]), do: nil
  defp first_time(evs), do: evs |> Enum.map(& &1.event_time) |> Enum.reject(&is_nil/1) |> Enum.min(DateTime, fn -> nil end)
  defp last_time([]), do: nil
  defp last_time(evs), do: evs |> Enum.map(& &1.event_time) |> Enum.reject(&is_nil/1) |> Enum.max(DateTime, fn -> nil end)

  defp group_by_category(classified) do
    grouped = Enum.group_by(classified, & &1.category)

    Enum.map(@categories, fn {key, label, hint, sev} ->
      items = Map.get(grouped, key, [])
      %{key: key, label: label, hint: hint, severity: sev, items: items, count: length(items)}
    end)
  end

  defp overall_risk(classified) do
    cond do
      Enum.any?(classified, &(&1.category in [:persistence, :privilege_escalation, :defense_evasion])) ->
        {:critical, "严重:攻击者已建立持久化或破坏防御,需按入侵事件处置"}

      Enum.any?(classified, &(&1.category in [:data_access, :destructive])) ->
        {:high, "高危:发生数据读取或资源删改"}

      Enum.any?(classified, &(&1.category == :resource_abuse)) ->
        {:medium, "中危:存在资源滥用"}

      Enum.any?(classified, &(&1.category == :recon)) ->
        {:low, "低危:仅发现侦察探测行为"}

      true ->
        {:info, "未发现敏感操作"}
    end
  end

  # ---------- 攻击经过(阶段化时间线) ----------

  @phase_order [:recon, :privilege_escalation, :persistence, :data_access, :resource_abuse, :defense_evasion, :destructive, :other]

  @phase_names %{
    recon: "① 侦察探测",
    privilege_escalation: "② 权限提升",
    persistence: "③ 植入持久化后门",
    data_access: "④ 数据窃取",
    resource_abuse: "⑤ 资源滥用",
    defense_evasion: "⑥ 清理痕迹 / 破坏防御",
    destructive: "⑦ 删除与破坏",
    other: "其他"
  }

  def phase_names, do: @phase_names

  defp build_timeline(classified) do
    # 按时间排序后,把相邻同类别事件合并为一个"步骤"
    classified
    |> Enum.sort_by(&(&1.event.event_time || ~U[1970-01-01 00:00:00Z]), DateTime)
    |> Enum.reduce([], fn item, acc ->
      case acc do
        [] ->
          [step(item)]

        [last | rest] ->
          if last.category == item.category and same_wave?(last, item) do
            [merge_step(last, item) | rest]
          else
            [step(item) | acc]
          end
      end
    end)
    |> Enum.reverse()
    |> Enum.with_index(1)
    |> Enum.map(fn {step, idx} -> Map.put(step, :index, idx) end)
  end

  # 同类事件间隔 30 分钟内视为同一波操作
  defp same_wave?(last, item) do
    case {last.last_time, item.event.event_time} do
      {%DateTime{} = t1, %DateTime{} = t2} -> abs(DateTime.diff(t2, t1, :second)) <= 1800
      _ -> false
    end
  end

  defp step(item) do
    %{
      category: item.category,
      phase: Map.get(@phase_names, item.category, "其他"),
      severity: item.severity,
      start_time: item.event.event_time,
      last_time: item.event.event_time,
      source_ip: item.event.source_ip,
      user_agent: item.event.user_agent,
      actions: [%{time: item.event.event_time, description: item.description, event: item.event}]
    }
  end

  defp merge_step(step, item) do
    %{
      step
      | last_time: item.event.event_time,
        severity: max_severity(step.severity, item.severity),
        actions: step.actions ++ [%{time: item.event.event_time, description: item.description, event: item.event}]
    }
  end

  @sev_rank %{info: 0, low: 1, medium: 2, high: 3, critical: 4}
  defp max_severity(a, b), do: if(@sev_rank[a] >= @sev_rank[b], do: a, else: b)

  def phase_order, do: @phase_order
end
