defmodule KeyscopeWeb.InvestigationController do
  use KeyscopeWeb, :controller

  alias Keyscope.Audit.{Investigator, Loader, Store}

  @sample_path Application.app_dir(:keyscope, "priv/samples/cloudtrail_leak.jsonl")

  def index(conn, _params) do
    %{events: events, source_name: source_name} = Store.get()

    render(conn, :index,
      page_title: "导入审计日志",
      loaded: events != [],
      source_name: source_name,
      key_index: Loader.key_index(events)
    )
  end

  def import(conn, params) do
    {text, source_name} = resolve_source(params)

    case text && Loader.parse(text) do
      nil ->
        conn |> put_flash(:error, "请粘贴日志内容、选择文件,或点击加载样例。") |> redirect(to: ~p"/")

      {:ok, events} ->
        Store.put(events, source_name)

        conn
        |> put_flash(:info, "已导入 #{length(events)} 条事件(#{source_name})")
        |> redirect(to: ~p"/")

      {:error, reason} ->
        conn |> put_flash(:error, "导入失败:#{reason}") |> redirect(to: ~p"/")
    end
  end

  def report(conn, %{"key_id" => key_id}) do
    %{events: events} = Store.get()

    if events == [] do
      conn |> put_flash(:error, "请先导入审计日志。") |> redirect(to: ~p"/")
    else
      report = Investigator.investigate(events, key_id)
      render(conn, :report, page_title: "调查报告 #{key_id}", report: report)
    end
  end

  defp resolve_source(%{"sample" => "1"}), do: {File.read!(@sample_path), "内置样例 cloudtrail_leak.jsonl"}

  defp resolve_source(%{"log_file" => %Plug.Upload{path: path, filename: name}}) do
    {File.read!(path), "上传文件 #{name}"}
  end

  defp resolve_source(%{"log_text" => text}) when is_binary(text) and text != "" do
    {text, "粘贴内容"}
  end

  defp resolve_source(_), do: {nil, nil}
end
