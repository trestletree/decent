defmodule Decent do
  @moduledoc """
  Documentation for `Decent`.
  """

  use Rustler, otp_app: :decent, crate: :decent

  def encrypt(_public_key, _plaintext, _signing_key \\ nil),
    do: :erlang.nif_error(:nif_not_loaded)

  def decrypt(_encrypted_data, _private_key, _passphrase \\ nil),
    do: :erlang.nif_error(:nif_not_loaded)
end
