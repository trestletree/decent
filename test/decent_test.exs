defmodule DecentTest do
  use ExUnit.Case
  doctest Decent

  test "encrypt and decrypt with passphrase" do
    pub_key_path = Path.expand("../priv/test_keys/decent.pub.asc", __DIR__)
    priv_key_path = Path.expand("../priv/test_keys/decent.priv.asc", __DIR__)
    priv_key_passphrase = "passphrase"

    plain_text = "this is a test"

    assert {:ok, encrypted} = Decent.encrypt(plain_text, pub_key_path)

    assert {:ok, decrypted} = Decent.decrypt(encrypted, priv_key_path, priv_key_passphrase)

    assert decrypted == plain_text
  end

  test "encrypt and decrypt without passphrase" do
    pub_key_path = Path.expand("../priv/test_keys/decent-without-passphrase.pub.asc", __DIR__)
    priv_key_path = Path.expand("../priv/test_keys/decent-without-passphrase.priv.asc", __DIR__)

    plain_text = "this is a test"

    assert {:ok, encrypted} = Decent.encrypt(plain_text, pub_key_path)

    assert {:ok, decrypted} = Decent.decrypt(encrypted, priv_key_path)

    assert decrypted == plain_text
  end

  test "decrypt with bad passphrase" do
    pub_key_path = Path.expand("../priv/test_keys/decent.pub.asc", __DIR__)
    priv_key_path = Path.expand("../priv/test_keys/decent.priv.asc", __DIR__)
    priv_key_passphrase = "bad passphrase"

    plain_text = "this is a test"

    assert {:ok, encrypted} = Decent.encrypt(plain_text, pub_key_path)

    assert {:error, "Incorrect passphrase"} =
             Decent.decrypt(encrypted, priv_key_path, priv_key_passphrase)
  end

  test "encrypt with bad public key" do
    pub_key_path = Path.expand("../priv/test_keys/bad.pub.asc", __DIR__)

    plain_text = "this is a test"

    assert {:error, "Invalid public key format"} = Decent.encrypt(plain_text, pub_key_path)
  end

  test "decrypt with a bad private key" do
    pub_key_path = Path.expand("../priv/test_keys/decent.pub.asc", __DIR__)
    priv_key_path = Path.expand("../priv/test_keys/bad.priv.asc", __DIR__)
    priv_key_passphrase = "passphrase"

    plain_text = "this is a test"

    assert {:ok, encrypted} = Decent.encrypt(plain_text, pub_key_path)

    assert {:error, "Invalid private key format"} =
             Decent.decrypt(encrypted, priv_key_path, priv_key_passphrase)

    assert {:error, "Invalid private key format"} =
             Decent.decrypt(encrypted, priv_key_path)
  end
end
