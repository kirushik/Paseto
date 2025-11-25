defmodule Paseto do
  @moduledoc """
  Main entry point for consumers. Will parse the provided payload and return a version struct.

  Tokens are broken up into several components:
  * version: v1, v2, v3, or v4 -- v4 recommended for new applications
  * purpose: Local or Public -- Local -> Symmetric Encryption for payload & Public -> Asymmetric Encryption for payload
  * payload: A signed or encrypted & b64 encoded string
  * footer: An optional value, often used for storing keyIDs or other similar info.
  * implicit_assertion: Additional authenticated data not stored in the token (v3/v4 only)

  Version recommendations:
  * v4 (Sodium Modern): Ed25519 + XChaCha20, recommended for new applications
  * v3 (NIST Modern): ECDSA P-384 + AES-256-CTR, for FIPS/NIST compliance
  * v2 (Sodium Compat): For legacy libsodium support
  * v1 (NIST Compat): For legacy NIST support
  """

  alias Paseto.{Token, V1, V2, V3, V4, Utils}

  @doc """
  Peek at the claims in a public token without verifying the signature.
  Not allowed for encrypted (local) tokens.
  """
  @spec peek(String.t()) :: {:ok, String.t()} | {:error, atom()}
  def peek(token) do
    case token do
      "v1.local." <> _rest ->
        {:error, :no_peek_for_encrypted_tokens}

      "v2.local." <> _rest ->
        {:error, :no_peek_for_encrypted_tokens}

      "v3.local." <> _rest ->
        {:error, :no_peek_for_encrypted_tokens}

      "v4.local." <> _rest ->
        {:error, :no_peek_for_encrypted_tokens}

      "v1.public." <> _rest ->
        V1.peek(token)

      "v2.public." <> _rest ->
        V2.peek(token)

      "v3.public." <> _rest ->
        V3.peek(token)

      "v4.public." <> _rest ->
        V4.peek(token)
    end
  end

  @doc """
  Handles parsing a token. Providing it just the entire token will return the
  `Paseto.Token` struct with all fields populated.

  # Examples:
      iex> token = "v2.public.VGhpcyBpcyBhIHRlc3QgbWVzc2FnZSe-sJyD2x_fCDGEUKDcvjU9y3jRHxD4iEJ8iQwwfMUq5jUR47J15uPbgyOmBkQCxNDydR0yV1iBR-GPpyE-NQw"
      iex> Paseto.parse_token(token, pk)
      {:ok,
        %Paseto.Token{
          footer: nil,
          payload: "This is a test message",
          purpose: "public",
          version: "v2"
        }}
  """
  @spec parse_token(String.t(), binary(), String.t()) :: {:ok, Token} | {:error, String.t()}
  def parse_token(token, public_key, implicit_assertion \\ "") do
    with {:ok, %Token{version: version, purpose: purpose, payload: payload, footer: footer}} <-
           Utils.parse_token(token),
         {:ok, verified_payload} <- _parse_token(version, purpose, payload, public_key, footer, implicit_assertion) do
      {:ok,
       %Token{
         version: version,
         purpose: purpose,
         payload: verified_payload,
         footer: decode_footer(footer)
       }}
    end
  end

  @spec _parse_token(String.t(), String.t(), String.t(), String.t(), String.t() | tuple(), String.t()) ::
          {:ok, String.t()} | {:error, String.t()}
  defp _parse_token(version, purpose, payload, pk, footer, implicit_assertion) do
    case String.downcase(version) do
      "v1" ->
        case purpose do
          "local" ->
            V1.decrypt(payload, pk, footer)

          "public" ->
            V1.verify(payload, pk, footer)
        end

      "v2" ->
        case purpose do
          "local" ->
            V2.decrypt(payload, pk, footer)

          "public" ->
            V2.verify(payload, pk, footer)
        end

      "v3" ->
        case purpose do
          "local" ->
            V3.decrypt(payload, pk, footer, implicit_assertion)

          "public" ->
            V3.verify(payload, pk, footer, implicit_assertion)
        end

      "v4" ->
        case purpose do
          "local" ->
            V4.decrypt(payload, pk, footer, implicit_assertion)

          "public" ->
            V4.verify(payload, pk, footer, implicit_assertion)
        end
    end
  end

  defp decode_footer(""), do: nil
  defp decode_footer(footer), do: Utils.b64_decode!(footer)

  @doc """
  Handles generating a token:

  Tokens are broken up into several components:
  * version: v1, v2, v3, or v4 -- v4 recommended for new applications
  * purpose: Local or Public -- Local -> Symmetric Encryption for payload & Public -> Asymmetric Encryption for payload
  * payload: A signed or encrypted & b64 encoded string
  * footer: An optional value, often used for storing keyIDs or other similar info.
  * implicit_assertion: Additional authenticated data not stored in the token (v3/v4 only)

  # Examples:
      iex> {:ok, pk, sk} = Salty.Sign.Ed25519.keypair()
      iex> token = generate_token("v2", "public", "This is a test message", sk)
      "v2.public.VGhpcyBpcyBhIHRlc3QgbWVzc2FnZSe-sJyD2x_fCDGEUKDcvjU9y3jRHxD4iEJ8iQwwfMUq5jUR47J15uPbgyOmBkQCxNDydR0yV1iBR-GPpyE-NQw"
      iex> Paseto.parse_token(token, pk)
      {:ok,
        %Paseto.Token{
        footer: nil,
        payload: "This is a test message",
        purpose: "public",
        version: "v2"
        }}
  """
  @spec generate_token(String.t(), String.t(), String.t(), binary, String.t(), String.t()) :: String.t() | {:error, String.t()}
  def generate_token(version, purpose, payload, secret_key, footer \\ "", implicit_assertion \\ "") do
    _generate_token(version, purpose, payload, secret_key, footer, implicit_assertion)
  end

  defp _generate_token(version, "public", payload, sk, footer, implicit_assertion) do
    with {:ok, version_mod} <- version_module(version) do
      # v1 and v2 don't support implicit assertions, v3 and v4 do
      if version in ["v3", "v4"] do
        version_mod.sign(payload, sk, footer, implicit_assertion)
      else
        version_mod.sign(payload, sk, footer)
      end
    end
  end

  defp _generate_token(version, "local", payload, sk, footer, implicit_assertion) do
    with {:ok, version_mod} <- version_module(version) do
      # v1 and v2 don't support implicit assertions, v3 and v4 do
      if version in ["v3", "v4"] do
        version_mod.encrypt(payload, sk, footer, implicit_assertion)
      else
        version_mod.encrypt(payload, sk, footer)
      end
    end
  end

  defp version_module(version) when is_binary(version) do
    version = String.upcase(version)

    try do
      {:ok, String.to_existing_atom("Elixir.Paseto.#{version}")}
    rescue RuntimeError ->
      {:error, "Invalid version selected. Only v1, v2, v3 & v4 supported."}
    end
  end
end
