defmodule KeyscopeWeb.Router do
  use KeyscopeWeb, :router

  pipeline :browser do
    plug :accepts, ["html"]
    plug :fetch_session
    plug :fetch_live_flash
    plug :put_root_layout, html: {KeyscopeWeb.Layouts, :root}
    plug :protect_from_forgery
    plug :put_secure_browser_headers
  end

  pipeline :api do
    plug :accepts, ["json"]
  end

  scope "/", KeyscopeWeb do
    pipe_through :browser

    get "/", InvestigationController, :index
    post "/import", InvestigationController, :import
    get "/report/:key_id", InvestigationController, :report
  end

  # Other scopes may use custom stacks.
  # scope "/api", KeyscopeWeb do
  #   pipe_through :api
  # end
end
