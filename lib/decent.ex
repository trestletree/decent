defmodule Decent do
  @moduledoc """
  Functions for encrypting and decrypting messages using PGP.
  """

  use Rustler, otp_app: :decent, crate: :decent

  @doc """
  Encrypts a message using a public key.
  """
  def encrypt(_message, _public_key_path),
    do: :erlang.nif_error(:nif_not_loaded)

  @doc """
  Decrypts a message using a private key.
  """
  def decrypt(_encrypted_message, _private_key_path, _private_key_passphrase \\ nil),
    do: :erlang.nif_error(:nif_not_loaded)
end
