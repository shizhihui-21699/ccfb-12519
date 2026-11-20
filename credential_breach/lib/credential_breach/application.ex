defmodule CredentialBreach.Application do
  # See https://elixir.hexdocs.pm/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    children = [
      CredentialBreachWeb.Telemetry,
      {DNSCluster, query: Application.get_env(:credential_breach, :dns_cluster_query) || :ignore},
      {Phoenix.PubSub, name: CredentialBreach.PubSub},
      # 进程内调查存储：导入的日志集与生成的报告保存在这里（无外部数据库）
      CredentialBreach.Audit.Store,
      # Start to serve requests, typically the last entry
      CredentialBreachWeb.Endpoint
    ]

    # See https://elixir.hexdocs.pm/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: CredentialBreach.Supervisor]
    Supervisor.start_link(children, opts)
  end

  # Tell Phoenix to update the endpoint configuration
  # whenever the application is updated.
  @impl true
  def config_change(changed, _new, removed) do
    CredentialBreachWeb.Endpoint.config_change(changed, removed)
    :ok
  end
end
