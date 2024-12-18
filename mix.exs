defmodule Decent.MixProject do
  use Mix.Project

  @source_url "https://github.com/trestletree/decent"
  @version "0.1.0-dev"
  @dev? String.ends_with?(@version, "-dev")
  @force_build? System.get_env("DECENT_BUILD") in ["1", "true"]

  def project do
    [
      app: :decent,
      name: "Decent",
      description: "Functions for encrypting and decrypting messages using PGP.",
      version: @version,
      elixir: "~> 1.17",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      package: package()
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
      {:rustler_precompiled, "~> 0.6.0"},

      ## Optional
      {:rustler, "~> 0.35.0", optional: not (@dev? or @force_build?)}
    ]
  end

  defp package do
    [
      files: [
        "lib",
        "native",
        "checksum-*.exs",
        "mix.exs",
        "README.md"
      ],
      links: %{
        "GitHub" => @source_url
      },
      maintainers: ["Justin Johnson"]
    ]
  end
end
