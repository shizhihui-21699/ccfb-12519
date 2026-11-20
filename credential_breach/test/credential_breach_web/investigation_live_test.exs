defmodule CredentialBreachWeb.InvestigationLiveTest do
  use CredentialBreachWeb.ConnCase, async: false

  import Phoenix.LiveViewTest

  setup do
    # 内存存储是全局进程，测试间显式清空
    CredentialBreach.Audit.Store.reset()
    :ok
  end

  test "首页渲染调查台与导入面板", %{conn: conn} do
    {:ok, view, html} = live(conn, ~p"/")
    assert html =~ "泄露密钥影响面调查台"
    assert has_element?(view, "#load-sample-btn")
    assert has_element?(view, "#upload-form")
  end

  test "载入内置样例后自动识别泄露密钥并生成报告", %{conn: conn} do
    {:ok, view, _html} = live(conn, ~p"/")

    view |> element("#load-sample-btn") |> render_click()
    # 组件通过 send 异步转发，重新渲染读取处理后的最新状态
    html = render(view)

    # 密钥选项出现，且自动预选泄露的那把
    assert has_element?(view, "#key-option-AKIA2X9F3QK7WCP4RT8M")
    # 总览的关键指标卡渲染
    assert html =~ "密钥相关调用"
    assert html =~ "数据外传量"
    # 吊销横幅
    assert html =~ "被吊销"
  end

  test "可在各标签页之间切换且内容正确", %{conn: conn} do
    {:ok, view, _html} = live(conn, ~p"/")
    view |> element("#load-sample-btn") |> render_click()

    # 数据泄露页：含敏感数据表
    view |> element("#tab-data") |> render_click()
    assert has_element?(view, "#data-table")
    assert render(view) =~ "customer_db_2026q3.parquet"

    # 账号与后门页：含后门用户与角色
    view |> element("#tab-backdoors") |> render_click()
    assert has_element?(view, "#new-users")
    assert render(view) =~ "backup-svc-monitor"
    assert render(view) =~ "ecs-task-helper"

    # 删改与规避页
    view |> element("#tab-destruction") |> render_click()
    assert has_element?(view, "#destruction-panel")
    assert render(view) =~ "prod-order-mysql-snap"

    # 攻击经过页：7 个阶段
    view |> element("#tab-timeline") |> render_click()
    assert has_element?(view, "#timeline")
    assert render(view) =~ "验证接入"
    assert render(view) =~ "吊销后尝试"

    # 原始调用页
    view |> element("#tab-raw") |> render_click()
    assert has_element?(view, "#raw-event-list")
  end

  test "原始调用支持类别过滤", %{conn: conn} do
    {:ok, view, _html} = live(conn, ~p"/")
    view |> element("#load-sample-btn") |> render_click()
    view |> element("#tab-raw") |> render_click()

    view
    |> element("button[phx-value-category='destruction']")
    |> render_click()

    # 过滤后展示破坏类事件
    assert has_element?(view, "#raw-event-list")
    assert render(view) =~ "StopInstances"
  end

  test "切换到另一把密钥会重建报告", %{conn: conn} do
    {:ok, view, _html} = live(conn, ~p"/")
    view |> element("#load-sample-btn") |> render_click()

    # jenkins-runner 的密钥只有少量正常调用
    html =
      view
      |> element("#key-option-AKIA4MQD8VJ2N7XYZL0P")
      |> render_click()

    assert html =~ "AKIA4MQD8VJ2N7XYZL0P"
    assert render(view) =~ "密钥相关调用"
  end

  test "重新开始会清空已加载的数据集", %{conn: conn} do
    {:ok, view, _html} = live(conn, ~p"/")
    view |> element("#load-sample-btn") |> render_click()
    assert has_element?(view, "#reset-btn")

    view |> element("#reset-btn") |> render_click()
    html = render(view)

    refute html =~ "reset-btn"
    assert has_element?(view, "#load-sample-btn")
    refute has_element?(view, "#invest-tabs")
  end

  test "粘贴 JSONL 可以完成一次完整导入", %{conn: conn} do
    single =
      Jason.encode!(%{
        "eventID" => "p1",
        "eventTime" => "2026-11-08T02:14:33Z",
        "eventSource" => "sts.amazonaws.com",
        "eventName" => "GetCallerIdentity",
        "readOnly" => true,
        "sourceIPAddress" => "185.220.101.44",
        "userAgent" => "aws-cli/2.17.0",
        "userIdentity" => %{"accessKeyId" => "AKIAPASTE0001", "userName" => "paste-user"},
        "requestParameters" => %{}
      })

    {:ok, view, _html} = live(conn, ~p"/")

    view
    |> form("#paste-form", %{pasted: single})
    |> render_submit()

    assert has_element?(view, "#key-option-AKIAPASTE0001")
  end
end
