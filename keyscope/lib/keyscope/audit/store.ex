defmodule Keyscope.Audit.Store do
  @moduledoc "本地单用户工具:保存最近一次导入的事件集。"
  use Agent

  def start_link(_opts) do
    Agent.start_link(fn -> %{events: [], source_name: nil} end, name: __MODULE__)
  end

  def put(events, source_name) do
    Agent.update(__MODULE__, fn _ -> %{events: events, source_name: source_name} end)
  end

  def get do
    Agent.get(__MODULE__, & &1)
  end
end
