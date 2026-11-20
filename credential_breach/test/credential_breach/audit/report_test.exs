defmodule CredentialBreach.Audit.ReportTest do
  use ExUnit.Case, async: true

  alias CredentialBreach.Audit.{Importer, Report}

  @leaked "AKIA2X9F3QK7WCP4RT8M"

  setup do
    {:ok, report: Report.build(Importer.load_sample!(), @leaked)}
  end

  test "只保留泄露密钥产生的调用，过滤掉其他身份的正常流量", %{report: report} do
    assert report.total_events == 51
    assert Enum.all?(report.events, &(&1.access_key_id == @leaked))
    # jenkins-runner / zhang.wei 等其他身份的事件不应出现
    refute Enum.any?(report.events, &(&1.user_name == "jenkins-runner"))
  end

  test "识别出泄露身份", %{report: report} do
    assert report.leaked_user == "ci-deploy-bot"
    assert report.leaked_arn =~ "ci-deploy-bot"
  end

  test "在全量日志中检测到吊销事件及操作人", %{report: report} do
    assert %DateTime{} = report.revoked_at
    assert report.revoked_by =~ "li.fang"
  end

  test "还原出完整的 7 个杀伤链阶段", %{report: report} do
    stages = Enum.map(report.stage_groups, & &1.stage)
    assert stages == [1, 2, 3, 4, 5, 6, 7]
    # 每个阶段都有叙事文案
    assert Enum.all?(report.stage_groups, &(String.length(&1.narrative) > 20))
  end

  test "汇总被读取/下载/导出的数据且统计外传字节", %{report: report} do
    assert length(report.data_accesses) == 9
    assert report.data_total_bytes > 4_000_000_000
    assert report.sensitive_count >= 5
    # 含 RDS 快照导出
    assert Enum.any?(report.data_accesses, &(&1.kind == "数据库快照导出"))
  end

  test "汇总新建账号与密钥，且排除吊销后的失败尝试", %{report: report} do
    names = Enum.map(report.new_identities.users, & &1.user_name)
    assert "backup-svc-monitor" in names
    # cto-admin 是被挂上新密钥的既有用户
    assert "cto-admin" in names
    # 吊销后失败的 CreateAccessKey 不应产生虚假身份
    refute "ci-deploy-bot" in names

    monitor = Enum.find(report.new_identities.users, &(&1.user_name == "backup-svc-monitor"))
    assert monitor.admin? == true
    assert monitor.console_login? == true
    assert monitor.access_keys == ["AKIAW7QD2XJ9F5THM8KE"]
  end

  test "识别开放信任的后门角色", %{report: report} do
    role_names = Enum.map(report.new_identities.roles, & &1.name)
    assert "ecs-task-helper" in role_names
    assert Enum.all?(report.new_identities.roles, & &1.open_assume?)
  end

  test "汇总策略/网络/存储后门", %{report: report} do
    # 含 S3 跨账号桶策略与实例 userData 植入
    assert Enum.any?(report.backdoors, &(&1.kind == "存储桶策略后门"))
    assert Enum.any?(report.backdoors, &(&1.kind == "实例 userData 植入"))

    ports =
      report.network_changes
      |> Enum.flat_map(& &1.rules)
      |> Enum.map(& &1.port)

    assert "22" in ports
    assert "6379" in ports
  end

  test "汇总审计规避动作", %{report: report} do
    names = Enum.map(report.evasions, & &1.event.event_name)
    assert "StopLogging" in names
    assert "UpdateTrail" in names
    assert "DeleteTrail" in names
  end

  test "汇总被删改/关停的资源", %{report: report} do
    resources = Enum.map(report.destructions, & &1.resource)
    assert length(report.destructions) == 4
    assert Enum.any?(resources, &String.contains?(&1, "nightly-2026-11-10.rds"))
    assert Enum.any?(resources, &String.contains?(&1, "prod-order-mysql-snap-20261108"))
    assert Enum.any?(resources, &String.contains?(&1, "i-0c88f1a2b3d4e5f60"))
  end

  test "吊销后的失败调用归入阶段 7", %{report: report} do
    stage7 = Enum.find(report.stage_groups, &(&1.stage == 7))
    assert stage7.count == 2
    assert Enum.all?(stage7.events, &(&1.category == :denied))
  end

  test "来源 IP 画像带威胁标签", %{report: report} do
    labels = Map.new(report.ip_summary, &{&1.ip, &1.label})
    assert labels["185.220.101.44"] =~ "Tor"
    assert labels["45.155.204.118"] =~ "C2"
  end

  test "对数据集中不存在的密钥返回空结果但不崩溃" do
    report = Report.build(Importer.load_sample!(), "AKIA-NON-EXISTENT")
    assert report.total_events == 0
    assert report.stage_groups == []
    assert report.revoked_at == nil
  end
end
