# Decent

A simple Pretty Good Privacy (PGP) Elixir library, wrapping functions from the [pgp Rust crate](https://crates.io/crates/pgp). Enables encrypting with a public key and decrypting with the corresponding private key.

## Installation

The package can be installed by adding `decent` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:decent, github: "trestletree/decent", branch: "main"}
  ]
end
```
