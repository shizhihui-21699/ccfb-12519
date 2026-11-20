defmodule CredentialBreach.Audit.Store do
  @moduledoc """
  进程内调查存储（GenServer）。

  本项目不依赖数据库：导入的数据集与生成的报告保存在这里，
  重启应用即清空，符合“本地模拟日志调查台”的定位。
  """

  use GenServer

  alias CredentialBreach.Audit.{Dataset, Report}

  @name __MODULE__

  # ---------- 客户端 API ----------

  def start_link(opts \\ []), do: GenServer.start_link(@name, opts, name: opts[:name] || @name)

  @doc "保存一次导入的数据集，返回数据集 ID。"
  def put_dataset(%Dataset{} = dataset), do: GenServer.call(@name, {:put_dataset, dataset})

  @doc "按 ID 取数据集。"
  def get_dataset(id), do: GenServer.call(@name, {:get_dataset, id})

  @doc "缓存一份报告。"
  def put_report(%Report{} = report), do: GenServer.call(@name, {:put_report, report})

  @doc "按 数据集ID + 泄露密钥 取缓存报告。"
  def get_report(dataset_id, leaked_key),
    do: GenServer.call(@name, {:get_report, dataset_id, leaked_key})

  @doc "清空全部状态（重新导入时调用）。"
  def reset, do: GenServer.call(@name, :reset)

  # ---------- 服务端 ----------

  @impl true
  def init(_opts), do: {:ok, %{datasets: %{}, reports: %{}}}

  @impl true
  def handle_call({:put_dataset, dataset}, _from, state) do
    id = "ds-#{:erlang.unique_integer([:positive])}"
    {:reply, id, put_in(state, [:datasets, id], dataset)}
  end

  def handle_call({:get_dataset, id}, _from, state),
    do: {:reply, Map.get(state.datasets, id), state}

  def handle_call({:put_report, report}, _from, state) do
    key = {report.dataset.source_name, report.leaked_key}
    {:reply, :ok, put_in(state, [:reports, key], report)}
  end

  def handle_call({:get_report, dataset_id, leaked_key}, _from, state) do
    case Map.get(state.datasets, dataset_id) do
      nil ->
        {:reply, nil, state}

      dataset ->
        report = Map.get(state.reports, {dataset.source_name, leaked_key})
        {:reply, report, state}
    end
  end

  def handle_call(:reset, _from, _state), do: {:reply, :ok, %{datasets: %{}, reports: %{}}}
end
