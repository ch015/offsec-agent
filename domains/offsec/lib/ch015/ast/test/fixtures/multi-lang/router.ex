defmodule MyAppWeb.Router do
  use MyAppWeb, :router

  pipeline :api do
    plug :accepts, ["json"]
  end

  scope "/api", MyAppWeb do
    pipe_through :api
    resources "/users", UserController
    get "/health", HealthController, :index
    post "/auth/login", AuthController, :login
  end
end
