defmodule CredentialBreach.Audit.Importer do
  @moduledoc """
  审计日志导入器。

  接受 JSONL（每行一条 CloudTrail 事件）文本，逐行解析、去重并按时间排序，
  返回 `%Dataset{}`。坏行不会中断导入，而是计数并保留样例供 UI 提示。
  """

  alias CredentialBreach.Audit.{Dataset, Event}

  @doc """
  解析 JSONL 文本。`source_name` 用于在 UI 上标识数据来源。
  """
  @spec parse(String.t(), String.t()) :: Dataset.t()
  def parse(content, source_name \\ "uploaded-audit.jsonl") when is_binary(content) do
    {events, bad_lines, total_lines} =
      content
      # 注意：不能用 ~r/\R/ —— PCRE 的 \R 在 UTF-8 模式下还匹配 U+0085，
      # 而中文多字节字符的尾字节可能恰好是 0x85，会把含中文的日志行从中间劈开。
      |> String.split("\n", trim: true)
      |> Enum.map(&String.trim/1)
      |> Enum.reject(&(&1 == ""))
      |> Enum.reduce({[], [], 0}, fn line, {acc, bad, count} ->
        case decode_line(line) do
          {:ok, raw} ->
            case Event.from_raw(raw) do
              %Event{} = event -> {[event | acc], bad, count + 1}
              _ -> {acc, [%{line: count + 1, reason: "字段映射失败"} | bad], count + 1}
            end

          {:error, reason} ->
            {acc, [%{line: count + 1, reason: reason} | bad], count + 1}
        end
      end)

    unique =
      events
      |> Enum.reverse()
      |> Enum.dedup_by(& &1.event_id)
      # 缺 eventTime 的容错记录排到最后，避免 nil 进入 DateTime 比较
      |> Enum.sort_by(&(&1.event_time || ~U[9999-12-31 23:59:59Z]), DateTime)

    %Dataset{
      source_name: source_name,
      imported_at: DateTime.utc_now(),
      total_lines: total_lines,
      bad_lines: Enum.reverse(bad_lines),
      events: unique
    }
  end

  @doc "读取内置的模拟云审计日志样例。"
  def load_sample! do
    path = Path.join(:code.priv_dir(:credential_breach), "sample_data/cloud_audit.jsonl")
    parse(File.read!(path), "cloud_audit.jsonl（内置模拟数据）")
  end

  defp decode_line(line) do
    case Jason.decode(line) do
      {:ok, %{} = raw} -> {:ok, raw}
      {:ok, _other} -> {:error, "顶层不是 JSON 对象"}
      {:error, %Jason.DecodeError{position: pos}} -> {:error, "JSON 语法错误（位置 #{pos}）"}
    end
  end
end
