defmodule CredentialBreach.Audit.ImporterTest do
  use ExUnit.Case, async: true

  alias CredentialBreach.Audit.{Dataset, Importer}

  @valid_event Jason.encode!(%{
                 "eventID" => "e1",
                 "eventTime" => "2026-11-08T02:14:33Z",
                 "eventSource" => "sts.amazonaws.com",
                 "eventName" => "GetCallerIdentity",
                 "eventType" => "AwsApiCall",
                 "readOnly" => true,
                 "managementEvent" => true,
                 "sourceIPAddress" => "185.220.101.44",
                 "userAgent" => "aws-cli/2.17.0",
                 "awsRegion" => "ap-southeast-1",
                 "recipientAccountId" => "619355712044",
                 "userIdentity" => %{
                   "type" => "IAMUser",
                   "arn" => "arn:aws:iam::619355712044:user/ci/ci-deploy-bot",
                   "accessKeyId" => "AKIATEST0001",
                   "userName" => "ci-deploy-bot"
                 },
                 "requestParameters" => %{}
               })

  test "解析合法 JSONL，按时间排序并归一化字段" do
    later =
      Jason.encode!(%{
        "eventID" => "e2",
        "eventTime" => "2026-11-09T03:00:00Z",
        "eventSource" => "s3.amazonaws.com",
        "eventName" => "GetObject",
        "readOnly" => true,
        "sourceIPAddress" => "1.1.1.1",
        "userAgent" => "aws-cli",
        "userIdentity" => %{"accessKeyId" => "AKIATEST0001", "userName" => "ci-deploy-bot"},
        "requestParameters" => %{"bucketName" => "b", "key" => "k"},
        "additionalEventData" => %{"bytesTransferredOut" => 2048}
      })

    dataset = Importer.parse("#{later}\n#{@valid_event}\n", "t.jsonl")

    assert %Dataset{} = dataset
    assert dataset.total_lines == 2
    assert dataset.bad_lines == []
    assert length(dataset.events) == 2
    # 按 event_time 升序：e1(11-08) 在 e2(11-09) 之前
    assert Enum.map(dataset.events, & &1.event_id) == ["e1", "e2"]
    # 服务名去掉 amazonaws.com 后缀
    assert List.first(dataset.events).event_source == "sts"
    # 外传字节从 additionalEventData 提取
    assert List.last(dataset.events).bytes_out == 2048
  end

  test "坏行被计数且不中断整体解析" do
    dataset = Importer.parse("#{@valid_event}\nnot-json-at-all\n{\"broken\":\n", "t.jsonl")

    assert dataset.total_lines == 3
    assert length(dataset.events) == 1
    assert length(dataset.bad_lines) == 2
    assert Enum.all?(dataset.bad_lines, &match?(%{line: _}, &1))
  end

  test "含中文的长行不会被多字节字符劈开（回归 U+0085 问题）" do
    chinese_event =
      Jason.encode!(%{
        "eventID" => "cn1",
        "eventTime" => "2026-11-09T13:18:05Z",
        "eventSource" => "s3.amazonaws.com",
        "eventName" => "GetObject",
        "readOnly" => true,
        "sourceIPAddress" => "1.1.1.1",
        "userAgent" => "aws-cli",
        "userIdentity" => %{"accessKeyId" => "AKIATEST0001", "userName" => "ci-deploy-bot"},
        "requestParameters" => %{
          "bucketName" => "fin-prod-data",
          # 内含“全员薪资与期权表”等中文，尾字节可能出现 0x85
          "key" => "hr/全员薪资与期权表_202610.xlsx"
        },
        "additionalEventData" => %{"bytesTransferredOut" => 4_728_103}
      })

    dataset = Importer.parse(chinese_event <> "\n", "t.jsonl")

    assert dataset.bad_lines == []
    assert length(dataset.events) == 1
    assert List.first(dataset.events).sensitive == true
  end

  test "相同 eventID 的重复事件被去重" do
    dup = String.replace(@valid_event, ~s("eventID":"e1"), ~s("eventID":"e1"))
    dataset = Importer.parse("#{@valid_event}\n#{dup}\n", "t.jsonl")
    assert length(dataset.events) == 1
  end

  test "内置样例可加载且无坏行" do
    dataset = Importer.load_sample!()
    assert dataset.total_lines > 50
    assert dataset.bad_lines == []
  end

  test "access_keys/1 按调用次数降序列出密钥" do
    dataset = Importer.load_sample!()
    keys = Dataset.access_keys(dataset)
    assert [{top_key, top_count} | _] = keys
    assert top_key == "AKIA2X9F3QK7WCP4RT8M"
    assert top_count >= 40
  end
end
