defmodule Decent.MixProject do
  use Mix.Project

  def project do
    [
      app: :decent,
      version: "0.1.0",
      elixir: "~> 1.17",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:rustler, "~> 0.35.0", optional: true},
      {:rustler_precompiled, "~> 0.6.0", runtime: false}
    ]
  end
end
