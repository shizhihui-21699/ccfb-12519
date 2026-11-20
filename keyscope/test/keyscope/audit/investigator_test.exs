defmodule Keyscope.Audit.InvestigatorTest do
  use ExUnit.Case, async: true

  alias Keyscope.Audit.{Investigator, Loader}

  @sample Application.app_dir(:keyscope, "priv/samples/cloudtrail_leak.jsonl") |> File.read!()
  @leaked_key "AKIA3X7KQZMWJPLM4V2T"

  setup do
    {:ok, events} = Loader.parse(@sample)
    %{events: events, report: Investigator.investigate(events, @leaked_key)}
  end

  test "样例日志可完整解析", %{events: events} do
    assert length(events) == 55
  end

  test "按密钥还原全部调用", %{report: r} do
    assert r.total == 50
    assert r.principals == ["chen.lei"]
    assert "45.155.204.117" in r.source_ips
    assert "185.220.101.4" in r.source_ips
    assert r.denied_count == 3
  end

  test "识别数据窃取", %{report: r} do
    data = find_cat(r, :data_access)
    descs = Enum.map(data.items, & &1.description)
    assert Enum.any?(descs, &String.contains?(&1, "acme-customer-backup"))
    assert Enum.any?(descs, &String.contains?(&1, "prod/mysql/order-db"))
    assert Enum.any?(descs, &String.contains?(&1, "stripe"))
  end

  test "识别持久化后门", %{report: r} do
    pers = find_cat(r, :persistence)
    descs = Enum.map(pers.items, & &1.description)
    assert Enum.any?(descs, &String.contains?(&1, "svc-backup-agent"))
    assert Enum.any?(descs, &String.contains?(&1, "AKIA9X1KQZMWJBACKDOOR"))
    assert Enum.any?(descs, &String.contains?(&1, "metrics-collector"))
    assert Enum.any?(descs, &String.contains?(&1, "安全组"))
  end

  test "识别权限提升与防御规避", %{report: r} do
    esc = find_cat(r, :privilege_escalation)
    assert Enum.any?(esc.items, &String.contains?(&1.description, "AdministratorAccess"))
    assert Enum.any?(esc.items, &String.contains?(&1.description, "deploy-role"))

    eva = find_cat(r, :defense_evasion)
    assert Enum.any?(eva.items, &String.contains?(&1.description, "CloudTrail"))
    assert Enum.any?(eva.items, &String.contains?(&1.description, "告警"))
  end

  test "识别删除破坏与资源滥用", %{report: r} do
    des = find_cat(r, :destructive)
    assert Enum.any?(des.items, &String.contains?(&1.description, "DeleteDBSnapshot") or String.contains?(&1.description, "快照"))

    abuse = find_cat(r, :resource_abuse)
    assert [%{description: d}] = abuse.items
    assert d =~ "4 台 g5.12xlarge"
  end

  test "综合风险为严重", %{report: r} do
    assert {:critical, _} = r.risk
  end

  test "时间线按时间排序且合并同类波次", %{report: r} do
    assert length(r.timeline) > 10
    times = Enum.map(r.timeline, & &1.start_time)
    assert times == Enum.sort(times, DateTime)

    # 侦察波次合并:攻击者 14:32-14:37 的 10 次探测应并为一步
    recon_step = Enum.find(r.timeline, fn s -> s.category == :recon and length(s.actions) >= 8 end)
    assert recon_step
    assert recon_step.source_ip == "45.155.204.117"
  end

  test "其他密钥不受影响", %{events: events} do
    r = Investigator.investigate(events, "AKIA8P2NQZMWJY6H3T4R")
    assert r.total == 2
    # 无持久化、权限提升、防御规避等入侵痕迹
    assert find_cat(r, :persistence).count == 0
    assert find_cat(r, :privilege_escalation).count == 0
    assert find_cat(r, :defense_evasion).count == 0
    assert find_cat(r, :destructive).count == 0
  end

  defp find_cat(report, key) do
    Enum.find(report.by_category, &(&1.key == key))
  end
end
