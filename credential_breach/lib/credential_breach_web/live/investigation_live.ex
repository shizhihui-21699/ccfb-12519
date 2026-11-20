defmodule CredentialBreachWeb.InvestigationLive do
  @moduledoc """
  泄露密钥影响面调查台主 LiveView。

  职责：
    1. 导入本地 JSONL 云审计日志（上传 / 内置样例 / 粘贴）
    2. 选择（或自动识别）泄露的访问密钥
    3. 生成并展示按密钥还原的调用、数据泄露、后门、破坏与攻击时间线
  """
  use CredentialBreachWeb, :live_view

  alias CredentialBreach.Investigations
  alias CredentialBreach.Audit.{Dataset, Report}

  @tabs [
    %{id: "overview", name: "总览", icon: "hero-squares-2x2"},
    %{id: "data", name: "数据泄露", icon: "hero-circle-stack"},
    %{id: "backdoors", name: "账号与后门", icon: "hero-key"},
    %{id: "destruction", name: "删改与规避", icon: "hero-trash"},
    %{id: "timeline", name: "攻击经过", icon: "hero-clock"},
    %{id: "raw", name: "原始调用", icon: "hero-list-bullet"}
  ]

  @impl true
  def mount(_params, _session, socket) do
    {:ok,
     socket
     |> assign(
       page_title: "泄露密钥影响面调查台",
       tab: "overview",
       dataset: nil,
       dataset_id: nil,
       access_keys: [],
       leaked_key: "",
       report: nil,
       filter_category: "all",
       filter_only_denied: false,
       upload_error: nil
     )
     |> allow_upload(:audit_file,
       accept: ~w(.jsonl .ndjson .txt application/json text/plain),
       max_entries: 1,
       max_file_size: 20 * 1024 * 1024
     )}
  end

  @impl true
  def handle_params(%{"tab" => tab}, _uri, socket)
      when tab in ["overview", "data", "backdoors", "destruction", "timeline", "raw"] do
    {:noreply, assign(socket, tab: tab)}
  end

  def handle_params(_params, _uri, socket), do: {:noreply, socket}

  # ---------- 上传（直接由本 LiveView 的表单触发）----------

  @impl true
  def handle_event("cancel_upload", %{"ref" => ref}, socket) do
    {:noreply, cancel_upload(socket, :audit_file, ref)}
  end

  def handle_event("validate_upload", _params, socket) do
    {:noreply, socket}
  end

  def handle_event("ingest_upload", _params, socket) do
    case consume_uploaded(socket) do
      {:ok, {content, filename}} ->
        {dataset_id, dataset} = Investigations.import_jsonl(content, filename)
        {:noreply, apply_dataset(socket, dataset_id, dataset)}

      {:error, msg} ->
        {:noreply, assign(socket, upload_error: msg)}
    end
  end

  # ---------- 密钥选择与报告 ----------

  def handle_event("select_key", %{"key" => key}, socket) do
    {:noreply, socket |> assign(leaked_key: key, report: nil) |> maybe_build_report()}
  end

  # ---------- 原始调用过滤 ----------

  def handle_event("filter_category", %{"category" => category}, socket) do
    {:noreply, assign(socket, filter_category: category)}
  end

  def handle_event("toggle_denied", _params, socket) do
    {:noreply, assign(socket, filter_only_denied: !socket.assigns.filter_only_denied)}
  end

  def handle_event("reset", _params, socket) do
    {:noreply, reset_state(socket)}
  end

  # ---------- 来自导入面板 LiveComponent 的转发 ----------

  @impl true
  def handle_info(:load_sample, socket) do
    {dataset_id, dataset} = Investigations.load_sample()
    {:noreply, apply_dataset(socket, dataset_id, dataset)}
  end

  def handle_info({:ingest_paste, %{"pasted" => pasted}}, socket) do
    if String.trim(pasted) == "" do
      {:noreply, assign(socket, upload_error: "粘贴内容为空，请先粘贴 JSONL 日志")}
    else
      {dataset_id, dataset} = Investigations.import_jsonl(pasted, "pasted-audit.jsonl")
      {:noreply, apply_dataset(socket, dataset_id, dataset)}
    end
  end

  def handle_info({:select_key, key}, socket) do
    {:noreply, socket |> assign(leaked_key: key, report: nil) |> maybe_build_report()}
  end

  def handle_info(:reset_investigation, socket) do
    {:noreply, reset_state(socket)}
  end

  defp consume_uploaded(socket) do
    case consume_uploaded_entries(socket, :audit_file, fn %{path: path}, entry ->
           {:ok, {File.read!(path), entry.client_name}}
         end) do
      [{:ok, {content, filename}}] -> {:ok, {content, filename}}
      [] -> {:error, "没有可读取的上传文件"}
      [_ | _] = _many -> {:error, "检测到多个文件，请只保留一个"}
    end
  end

  defp apply_dataset(socket, dataset_id, %Dataset{} = dataset) do
    keys = Investigations.list_access_keys(dataset)
    leaked = guess_leaked_key(keys, dataset)

    socket
    |> assign(
      dataset: dataset,
      dataset_id: dataset_id,
      access_keys: keys,
      leaked_key: leaked,
      report: nil,
      upload_error: nil,
      filter_category: "all",
      filter_only_denied: false
    )
    |> maybe_build_report()
  end

  defp reset_state(socket) do
    Investigations.reset()

    assign(socket,
      dataset: nil,
      dataset_id: nil,
      access_keys: [],
      leaked_key: "",
      report: nil,
      upload_error: nil,
      filter_category: "all",
      filter_only_denied: false,
      tab: "overview"
    )
  end

  # ---------- 渲染 ----------

  @impl true
  def render(assigns) do
    ~H"""
    <Layouts.app flash={@flash} current_scope={%{}}>
      <div class="mx-auto max-w-7xl space-y-6">
        <CredentialBreachWeb.InvestigationLive.Intro.render />

        <.live_component
          module={CredentialBreachWeb.ImportPanel}
          id="import-panel"
          dataset={@dataset}
          upload_error={@upload_error}
          access_keys={@access_keys}
          leaked_key={@leaked_key}
          uploads_conf={@uploads}
        />

        <div :if={@report} class="space-y-6">
          <nav id="invest-tabs" class="tabs tabs-box bg-base-200/70 p-1 gap-1 overflow-x-auto">
            <.link
              :for={tab <- tabs()}
              id={"tab-#{tab.id}"}
              patch={~p"/?tab=#{tab.id}"}
              class={[
                "tab gap-1.5 text-sm font-medium transition-colors",
                @tab == tab.id && "tab-active bg-base-100 shadow-sm"
              ]}
            >
              <.icon name={tab.icon} class="size-4" />
              {tab.name}
            </.link>
          </nav>

          <CredentialBreachWeb.InvestigationLive.Overview.render
            :if={@tab == "overview"}
            report={@report}
          />
          <CredentialBreachWeb.InvestigationLive.DataPanel.render
            :if={@tab == "data"}
            report={@report}
          />
          <CredentialBreachWeb.InvestigationLive.Backdoors.render
            :if={@tab == "backdoors"}
            report={@report}
          />
          <CredentialBreachWeb.InvestigationLive.Destruction.render
            :if={@tab == "destruction"}
            report={@report}
          />
          <CredentialBreachWeb.InvestigationLive.Timeline.render
            :if={@tab == "timeline"}
            report={@report}
          />
          <CredentialBreachWeb.InvestigationLive.RawEvents.render
            :if={@tab == "raw"}
            report={@report}
            filter_category={@filter_category}
            filter_only_denied={@filter_only_denied}
          />
        </div>
      </div>
    </Layouts.app>
    """
  end

  # ---------- 辅助 ----------

  defp maybe_build_report(%{assigns: %{dataset_id: nil}} = socket), do: socket

  defp maybe_build_report(%{assigns: %{leaked_key: ""}} = socket), do: socket

  defp maybe_build_report(socket) do
    case Investigations.build_report(socket.assigns.dataset_id, socket.assigns.leaked_key) do
      {:ok, %Report{} = report} ->
        assign(socket, report: report)

      {:error, _} ->
        put_flash(socket, :error, "报告生成失败，请重新导入日志")
    end
  end

  # 选泄露密钥：优先非 CI/控制台的 IAM 用户密钥里调用最多的
  defp guess_leaked_key([], _dataset), do: ""

  defp guess_leaked_key(keys, %Dataset{} = dataset) do
    by_key = Map.new(dataset.events, fn e -> {e.access_key_id, e.user_name} end)

    Enum.find_value(keys, fn {key, _count} ->
      user = Map.get(by_key, key, "")
      if user not in ["jenkins-runner"] and key != "", do: key
    end) || elem(hd(keys), 0)
  end

  defp tabs, do: @tabs
end
