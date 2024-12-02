defmodule Decent do
  @moduledoc """
  Documentation for `Decent`.
  """

  use Rustler, otp_app: :decent, crate: :decent

  def add(_a, _b), do: :erlang.nif_error(:nif_not_loaded)
end
