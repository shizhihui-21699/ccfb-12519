defmodule Keyscope.Audit.Event do
  @moduledoc """
  一条云审计日志事件(以 AWS CloudTrail 格式为基准,兼容字段子集)。
  """

  @enforce_keys [:event_time, :event_source, :event_name]
  defstruct [
    :event_time,
    :event_source,
    :event_name,
    :access_key_id,
    :principal,
    :principal_arn,
    :account_id,
    :source_ip,
    :user_agent,
    :region,
    :error_code,
    :error_message,
    :request_params,
    :response_elements,
    :resources,
    :raw
  ]

  @type t :: %__MODULE__{}

  @doc "从 CloudTrail 风格的 map 构造事件;字段缺失时尽量容错。"
  def from_map(m) when is_map(m) do
    identity = m["userIdentity"] || %{}

    %__MODULE__{
      event_time: parse_time(m["eventTime"]),
      event_source: m["eventSource"] || "unknown",
      event_name: m["eventName"] || "Unknown",
      access_key_id: identity["accessKeyId"] || m["accessKeyId"],
      principal: principal_name(identity),
      principal_arn: identity["arn"],
      account_id: identity["accountId"] || m["recipientAccountId"],
      source_ip: m["sourceIPAddress"],
      user_agent: m["userAgent"],
      region: m["awsRegion"],
      error_code: m["errorCode"],
      error_message: m["errorMessage"],
      request_params: m["requestParameters"] || %{},
      response_elements: m["responseElements"] || %{},
      resources: m["resources"] || [],
      raw: m
    }
  end

  defp principal_name(%{"type" => "IAMUser", "userName" => name}), do: name
  defp principal_name(%{"type" => "AssumedRole", "arn" => arn}), do: "assumed:" <> arn
  defp principal_name(%{"userName" => name}), do: name
  defp principal_name(%{"principalId" => id}), do: id
  defp principal_name(_), do: "unknown"

  defp parse_time(nil), do: nil

  defp parse_time(s) when is_binary(s) do
    case DateTime.from_iso8601(s) do
      {:ok, dt, _} -> dt
      _ -> nil
    end
  end

  @doc "事件是否成功(无错误码视为成功)。"
  def success?(%__MODULE__{error_code: nil}), do: true
  def success?(_), do: false

  @doc "服务短名: s3.amazonaws.com -> s3"
  def service(%__MODULE__{event_source: src}) do
    src |> String.split(".") |> hd()
  end
end
