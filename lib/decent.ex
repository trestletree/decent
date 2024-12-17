defmodule Decent do
  @moduledoc """
  Functions for encrypting and decrypting messages using PGP.
  """

  use RustlerPrecompiled,
    otp_app: :decent,
    crate: :decent,
    base_url: "https://github.com/trestletree/decent/releases/download/v0.1.1",
    version: "0.1.1",
    force_build: System.get_env("DECENT_BUILD") in ["1", "true"]

  @doc """
  Encrypts a message using a public key.
  """
  def encrypt(_message, _public_key),
    do: :erlang.nif_error(:nif_not_loaded)

  @doc """
  Decrypts a message using a private key.
  """
  def decrypt(_encrypted_message, _private_key, _private_key_passphrase \\ nil),
    do: :erlang.nif_error(:nif_not_loaded)
end
