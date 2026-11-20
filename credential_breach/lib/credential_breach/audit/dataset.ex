defmodule CredentialBreach.Audit.Dataset do
  @moduledoc "一次导入的完整审计日志集合及其解析质量指标。"

  alias CredentialBreach.Audit.Event

  defstruct [
    :source_name,
    :imported_at,
    total_lines: 0,
    bad_lines: [],
    events: []
  ]

  @type t :: %__MODULE__{
          source_name: String.t(),
          imported_at: DateTime.t(),
          total_lines: non_neg_integer(),
          bad_lines: list(map()),
          events: list(Event.t())
        }

  @doc "数据集中出现过的全部访问密钥 ID 及其调用次数，按次数降序。"
  def access_keys(%__MODULE__{events: events}) do
    events
    |> Enum.reject(&(&1.access_key_id == ""))
    |> Enum.frequencies_by(& &1.access_key_id)
    |> Enum.sort_by(fn {_key, count} -> count end, :desc)
  end
end
