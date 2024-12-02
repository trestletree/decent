defmodule DecentTest do
  use ExUnit.Case
  doctest Decent

  test "encrypt and decrypt" do
    pub_key_path = Path.expand("../priv/test_keys/decent.pub.asc", __DIR__)
    priv_key_path = Path.expand("../priv/test_keys/decent.priv.asc", __DIR__)
    priv_key_passphrase = "passphrase"

    plain_text = "this is a test"

    assert {:ok, encrypted} = Decent.encrypt(plain_text, pub_key_path)

    assert {:ok, decrypted} = Decent.decrypt(encrypted, priv_key_path, priv_key_passphrase)

    assert decrypted == plain_text
  end
end
