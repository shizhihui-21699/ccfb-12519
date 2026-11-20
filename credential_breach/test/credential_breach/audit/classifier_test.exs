defmodule CredentialBreach.Audit.ClassifierTest do
  use ExUnit.Case, async: true

  alias CredentialBreach.Audit.{Classifier, Event}

  defp event(attrs) do
    Map.merge(
      %Event{
        event_id: "test-event-1",
        event_time: ~U[2026-11-08 02:14:33Z],
        event_source: "s3",
        event_name: "GetObject",
        request_params: %{},
        response_elements: %{},
        success: true
      },
      Map.new(attrs)
    )
  end

  test "GetCallerIdentity 归入阶段 1 验证接入" do
    e = Classifier.classify(event(event_name: "GetCallerIdentity", event_source: "sts"))
    assert e.category == :recon
    assert e.stage == 1
    assert e.severity == :low
    assert String.contains?(e.title, "验证泄露密钥")
  end

  test "带 errorCode 的事件归类为被拒调用" do
    e =
      Classifier.classify(
        event(event_name: "GetBucketPolicy", error_code: "AccessDenied", success: false)
      )

    assert e.category == :denied
    assert e.stage == 2
  end

  test "CreateUser 与 AttachUserPolicy 是严重后门动作" do
    create =
      Classifier.classify(
        event(event_name: "CreateUser", event_source: "iam", request_params: %{"userName" => "x"})
      )

    assert create.category == :backdoor_identity
    assert create.stage == 4
    assert create.severity == :critical

    attach =
      Classifier.classify(
        event(
          event_name: "AttachUserPolicy",
          event_source: "iam",
          request_params: %{
            "userName" => "x",
            "policyArn" => "arn:aws:iam::aws:policy/AdministratorAccess"
          }
        )
      )

    assert attach.category == :backdoor_permission
    assert String.contains?(attach.summary, "AdministratorAccess")
  end

  test "StopLogging/DeleteTrail 归入审计规避且为严重级" do
    for name <- ["StopLogging", "DeleteTrail"] do
      e =
        Classifier.classify(
          event(
            event_name: name,
            event_source: "cloudtrail",
            request_params: %{"name" => "trail"}
          )
        )

      assert e.category == :defense_evasion
      assert e.stage == 5
      assert e.severity == :critical
    end
  end

  test "删除备份与快照归入破坏清除阶段" do
    e =
      Classifier.classify(
        event(
          event_name: "DeleteDBSnapshot",
          event_source: "rds",
          request_params: %{"dbSnapshotIdentifier" => "snap-1"}
        )
      )

    assert e.category == :destruction
    assert e.stage == 6
    assert e.severity == :critical
  end

  test "命中 PII/薪资关键词的对象下载被标记为敏感" do
    e =
      Classifier.classify(
        event(
          event_name: "GetObject",
          event_source: "s3",
          request_params: %{"bucketName" => "fin", "key" => "hr/全员薪资与期权表.xlsx"}
        )
      )

    assert e.category == :data_access
    assert e.stage == 3
    assert e.sensitive == true
  end

  test "普通对象下载不标记敏感" do
    e =
      Classifier.classify(
        event(
          event_name: "GetObject",
          event_source: "s3",
          request_params: %{"bucketName" => "b", "key" => "a.txt"}
        )
      )

    assert e.sensitive == false
  end

  test "安全组放行 0.0.0.0/0 归入网络后门并解析端口" do
    e =
      Classifier.classify(
        event(
          event_name: "AuthorizeSecurityGroupIngress",
          event_source: "ec2",
          request_params: %{
            "groupId" => "sg-1",
            "ipPermissions" => [
              %{
                "ipProtocol" => "tcp",
                "fromPort" => 22,
                "toPort" => 22,
                "ipRanges" => [%{"cidrIp" => "0.0.0.0/0"}]
              }
            ]
          }
        )
      )

    assert e.category == :backdoor_network
    assert e.stage == 4
    assert String.contains?(e.summary, "22")
    assert String.contains?(e.summary, "0.0.0.0/0")
  end
end
