defmodule Keyscope.Application do
  # See https://elixir.hexdocs.pm/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    children = [
      KeyscopeWeb.Telemetry,
      {DNSCluster, query: Application.get_env(:keyscope, :dns_cluster_query) || :ignore},
      {Phoenix.PubSub, name: Keyscope.PubSub},
      Keyscope.Audit.Store,
      # Start a worker by calling: Keyscope.Worker.start_link(arg)
      # {Keyscope.Worker, arg},
      # Start to serve requests, typically the last entry
      KeyscopeWeb.Endpoint
    ]

    # See https://elixir.hexdocs.pm/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: Keyscope.Supervisor]
    Supervisor.start_link(children, opts)
  end

  # Tell Phoenix to update the endpoint configuration
  # whenever the application is updated.
  @impl true
  def config_change(changed, _new, removed) do
    KeyscopeWeb.Endpoint.config_change(changed, removed)
    :ok
  end
end
