defmodule CredentialBreach.Audit.Event do
  @moduledoc """
  一条归一化后的云审计事件（CloudTrail 风格）。

  原始 JSON 日志经过 `from_raw/1` 解析后，统一映射为本结构体，
  供分类器、报告生成器与 LiveView 使用。
  """

  @derive {Jason.Encoder, except: [:raw]}
  defstruct [
    :event_id,
    :event_time,
    :event_source,
    :event_name,
    :aws_region,
    :source_ip,
    :user_agent,
    :identity_type,
    :principal_id,
    :arn,
    :account_id,
    :access_key_id,
    :user_name,
    :request_params,
    :response_elements,
    :read_only,
    :management_event,
    :error_code,
    :error_message,
    :bytes_out,
    :raw,
    category: :other,
    stage: 0,
    severity: :info,
    sensitive: false,
    success: true,
    title: "",
    summary: ""
  ]

  @type t :: %__MODULE__{}

  @doc """
  把一条原始 CloudTrail JSON（map）转成归一化事件。
  解析失败会抛出 `ArgumentError`，由 Importer 捕获并计入坏行。
  """
  def from_raw(%{} = raw) do
    identity = Map.get(raw, "userIdentity", %{})
    additional = Map.get(raw, "additionalEventData", %{})
    request = Map.get(raw, "requestParameters") || %{}
    response = Map.get(raw, "responseElements")

    error_code = Map.get(raw, "errorCode")

    %__MODULE__{
      event_id: Map.get(raw, "eventID"),
      event_time: parse_time(Map.get(raw, "eventTime")),
      event_source: normalize_source(Map.get(raw, "eventSource", "")),
      event_name: Map.get(raw, "eventName", ""),
      aws_region: Map.get(raw, "awsRegion", ""),
      source_ip: Map.get(raw, "sourceIPAddress", ""),
      user_agent: Map.get(raw, "userAgent", ""),
      identity_type: Map.get(identity, "type", ""),
      principal_id: Map.get(identity, "principalId", ""),
      arn: Map.get(identity, "arn", ""),
      account_id: Map.get(raw, "recipientAccountId") || Map.get(identity, "accountId", ""),
      access_key_id: Map.get(identity, "accessKeyId", ""),
      user_name: Map.get(identity, "userName", ""),
      request_params: request,
      response_elements: response,
      read_only: Map.get(raw, "readOnly", false),
      management_event: Map.get(raw, "managementEvent", false),
      error_code: error_code,
      error_message: Map.get(raw, "errorMessage"),
      bytes_out: Map.get(additional, "bytesTransferredOut") || content_length(response, request),
      raw: raw,
      success: is_nil(error_code)
    }
    |> CredentialBreach.Audit.Classifier.classify()
  end

  defp parse_time(nil), do: nil

  defp parse_time(str) when is_binary(str) do
    case DateTime.from_iso8601(str) do
      {:ok, dt, _offset} -> dt
      {:error, _} -> nil
    end
  end

  # s3.amazonaws.com -> s3；signin.amazonaws.com -> signin
  defp normalize_source(source) do
    source |> String.replace_suffix(".amazonaws.com", "")
  end

  defp content_length(%{"contentLength" => n}, _) when is_integer(n), do: n
  defp content_length(_, %{"contentLength" => n}) when is_integer(n), do: n
  defp content_length(_, _), do: nil
end
