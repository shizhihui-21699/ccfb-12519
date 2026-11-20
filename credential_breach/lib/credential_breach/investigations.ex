defmodule CredentialBreach.Investigations do
  @moduledoc """
  调查台的领域上下文：Web 层通过本模块完成日志导入、密钥选择与报告生成，
  不直接触碰 GenServer 与解析细节。
  """

  alias CredentialBreach.Audit.{Dataset, Importer, Report, Store}

  @doc "解析 JSONL 文本并入库，返回 {数据集ID, 数据集}。"
  def import_jsonl(content, source_name) do
    dataset = Importer.parse(content, source_name)
    {Store.put_dataset(dataset), dataset}
  end

  @doc "载入内置模拟日志并入库。"
  def load_sample do
    dataset = Importer.load_sample!()
    {Store.put_dataset(dataset), dataset}
  end

  @doc "按泄露密钥生成影响面报告（带进程内缓存）。"
  def build_report(dataset_id, leaked_key) do
    case Store.get_dataset(dataset_id) do
      nil ->
        {:error, :not_found}

      %Dataset{} = dataset ->
        report =
          case Store.get_report(dataset_id, leaked_key) do
            nil ->
              report = Report.build(dataset, leaked_key)
              Store.put_report(report)
              report

            cached ->
              cached
          end

        {:ok, report}
    end
  end

  @doc "列出数据集中的全部访问密钥及调用次数。"
  def list_access_keys(%Dataset{} = dataset), do: Dataset.access_keys(dataset)

  def get_dataset(dataset_id), do: Store.get_dataset(dataset_id)

  def reset, do: Store.reset()
end
