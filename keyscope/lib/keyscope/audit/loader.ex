defmodule Keyscope.Audit.Loader do
  @moduledoc """
  审计日志导入:支持三种常见形态
    1. JSONL —— 每行一条 CloudTrail 事件
    2. CloudTrail 批量文件 —— {"Records": [...]}(可整体一行或格式化多行)
    3. 顶层 JSON 数组 —— [...]
  """

  alias Keyscope.Audit.Event

  @doc "从文本解析事件列表,返回 {:ok, [Event.t]} | {:error, reason}"
  def parse(text) when is_binary(text) do
    text = String.trim(text)

    cond do
      text == "" ->
        {:error, "内容为空"}

      String.starts_with?(text, "[") ->
        parse_array(text)

      String.starts_with?(text, "{") and String.contains?(text, "\"Records\"") and
          not String.contains?(text, "\n{") ->
        parse_records_wrapper(text)

      true ->
        parse_jsonl(text)
    end
  end

  defp parse_array(text) do
    case Jason.decode(text) do
      {:ok, list} when is_list(list) ->
        {:ok, list |> Enum.filter(&is_map/1) |> Enum.map(&Event.from_map/1)}

      {:ok, %{"Records" => list}} when is_list(list) ->
        {:ok, Enum.map(list, &Event.from_map/1)}

      {:error, err} ->
        {:error, "JSON 数组解析失败: #{Exception.message(err)}"}
    end
  end

  defp parse_records_wrapper(text) do
    case Jason.decode(text) do
      {:ok, %{"Records" => list}} when is_list(list) ->
        {:ok, Enum.map(list, &Event.from_map/1)}

      _ ->
        parse_jsonl(text)
    end
  end

  defp parse_jsonl(text) do
    events =
      text
      |> String.split("\n", trim: true)
      |> Enum.reduce_while({:ok, []}, fn line, {:ok, acc} ->
        case Jason.decode(line) do
          {:ok, %{"Records" => list}} when is_list(list) ->
            {:cont, {:ok, Enum.map(list, &Event.from_map/1) ++ acc}}

          {:ok, m} when is_map(m) ->
            {:cont, {:ok, [Event.from_map(m) | acc]}}

          {:error, err} ->
            {:halt, {:error, "第 #{length(acc) + 1} 行解析失败: #{Exception.message(err)}"}}
        end
      end)

    case events do
      {:ok, list} -> {:ok, Enum.reverse(list)}
      err -> err
    end
  end

  @doc "日志中出现的全部访问密钥 ID 及其调用次数,供导入后选择调查对象。"
  def key_index(events) do
    events
    |> Enum.filter(& &1.access_key_id)
    |> Enum.group_by(& &1.access_key_id)
    |> Enum.map(fn {key, evs} ->
      %{
        key_id: key,
        count: length(evs),
        principals: evs |> Enum.map(& &1.principal) |> Enum.uniq(),
        first_seen: evs |> Enum.map(& &1.event_time) |> Enum.reject(&is_nil/1) |> Enum.min(DateTime, fn -> nil end),
        last_seen: evs |> Enum.map(& &1.event_time) |> Enum.reject(&is_nil/1) |> Enum.max(DateTime, fn -> nil end)
      }
    end)
    |> Enum.sort_by(& &1.count, :desc)
  end
end
