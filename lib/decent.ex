defmodule Decent do
  @moduledoc """
  Documentation for `Decent`.
  """

  use Rustler, otp_app: :decent, crate: :decent

  def encrypt(_plaintext, _public_key_path),
    do: :erlang.nif_error(:nif_not_loaded)

  def decrypt(_ciphertext, _private_key_path, _passphrase \\ nil),
    do: :erlang.nif_error(:nif_not_loaded)
end
