defmodule Paseto.V4 do
  @moduledoc """
  The Version4 implementation of the Paseto protocol.

  More information about the implementation can be found here:
  1.) https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md

  v4 uses libsodium-based modern cryptography:
  - v4.local: XChaCha20 encryption with BLAKE2b for key derivation and MAC
  - v4.public: Ed25519 signatures

  Key differences from v2:
  - Uses BLAKE2b for key derivation instead of using nonce directly
  - Supports implicit assertions for additional authenticated data
  - Improved key commitment properties
  """

  @behaviour Paseto.VersionBehaviour

  alias Paseto.Token
  alias Paseto.Utils
  alias Paseto.Utils.Crypto
  alias Salty.Sign.Ed25519

  import Paseto.Utils, only: [b64_decode!: 1]

  require Logger

  @required_keys [:version, :purpose, :payload]
  @all_keys @required_keys ++ [:footer]

  @enforce_keys @all_keys
  defstruct @all_keys

  @spec from_token(Token.t()) :: %__MODULE__{}
  def from_token(token) do
    %__MODULE__{
      version: token.version,
      purpose: token.purpose,
      payload: token.payload,
      footer: token.footer
    }
  end

  @header_public "v4.public."
  @header_local "v4.local."

  @key_len 32
  @nonce_len 32

  @doc """
  Handles encrypting the payload and returning a valid token.

  v4.local uses:
  - 32-byte random nonce
  - BLAKE2b for key derivation
  - XChaCha20 for encryption
  - BLAKE2b-MAC for authentication

  # Examples:
      iex> key = :crypto.strong_rand_bytes(32)
      iex> Paseto.V4.encrypt("This is a test message", key)
      "v4.local...."
  """
  @spec encrypt(String.t(), binary, String.t(), String.t(), binary | nil) ::
          String.t() | {:error, String.t()}
  def encrypt(data, key, footer \\ "", implicit_assertion \\ "", n \\ nil) do
    aead_encrypt(data, key, footer, implicit_assertion, n || :crypto.strong_rand_bytes(@nonce_len))
  end

  @doc """
  Handles decrypting a token payload given the correct key.

  # Examples:
      iex> key = :crypto.strong_rand_bytes(32)
      iex> token = Paseto.V4.encrypt("This is a test message", key)
      iex> Paseto.V4.decrypt(token, key)
      {:ok, "This is a test message"}
  """
  @spec decrypt(String.t(), binary, String.t(), String.t()) ::
          {:ok, String.t()} | {:error, String.t()}
  def decrypt(data, key, footer \\ "", implicit_assertion \\ "") do
    aead_decrypt(data, key, footer, implicit_assertion)
  end

  @doc """
  Handles signing the token for public use.

  v4.public uses Ed25519 with implicit assertion support.

  # Examples:
      iex> {:ok, pk, sk} = Salty.Sign.Ed25519.keypair()
      iex> Paseto.V4.sign("Test Message", sk)
      "v4.public...."
  """
  @spec sign(String.t(), binary, String.t(), String.t()) :: String.t() | {:error, String.t()}
  def sign(data, secret_key, footer \\ "", implicit_assertion \\ "")
      when byte_size(secret_key) == 64 do
    pre_auth_encode = Utils.pre_auth_encode([@header_public, data, footer, implicit_assertion])

    {:ok, sig} = Ed25519.sign_detached(pre_auth_encode, secret_key)

    Utils.b64_encode_token(@header_public, data <> sig, footer)
  rescue
    _ -> {:error, "Signing failure."}
  end

  @doc """
  Handles verifying the signature belongs to the provided key.

  # Examples:
      iex> {:ok, pk, sk} = Salty.Sign.Ed25519.keypair()
      iex> token = Paseto.V4.sign("Test Message", sk)
      iex> Paseto.V4.verify(token, pk)
      {:ok, "Test Message"}
  """
  @spec verify(String.t(), binary, String.t(), String.t()) :: {:ok, binary} | {:error, String.t()}
  def verify(signed_message, public_key, footer \\ "", implicit_assertion \\ "") do
    decoded_footer = b64_decode!(footer)
    decoded_message = b64_decode!(signed_message)

    data_size = byte_size(decoded_message) - 64
    <<data::binary-size(data_size), sig::binary-64>> = decoded_message

    pre_auth_encode = Utils.pre_auth_encode([@header_public, data, decoded_footer, implicit_assertion])

    :ok = Ed25519.verify_detached(sig, pre_auth_encode, public_key)
    {:ok, data}
  rescue
    _ -> {:error, "Failed to verify signature."}
  end

  @doc """
  Allows looking at the claims without having verified them.
  """
  @spec peek(token :: String.t()) :: String.t()
  def peek(token) do
    {:ok, %Paseto.Token{payload: payload}} = Utils.parse_token(token)

    get_claims_from_signed_message(payload)
  end

  ##############################
  # Internal Private Functions #
  ##############################

  @spec get_claims_from_signed_message(signed_message :: String.t()) :: String.t()
  defp get_claims_from_signed_message(signed_message) do
    decoded_message = b64_decode!(signed_message)
    data_size = byte_size(decoded_message) - 64
    <<data::binary-size(data_size), _sig::binary-64>> = decoded_message

    data
  end

  @spec aead_encrypt(String.t(), binary, String.t(), String.t(), binary) ::
          String.t() | {:error, String.t()}
  defp aead_encrypt(_data, key, _footer, _implicit_assertion, _n)
       when byte_size(key) != @key_len do
    {:error, "Invalid key length. Expected #{@key_len}, but got #{byte_size(key)}"}
  end

  defp aead_encrypt(data, key, footer, implicit_assertion, n)
       when byte_size(key) == @key_len and byte_size(n) == @nonce_len do
    # Derive encryption key and nonce using BLAKE2b
    # tmp = BLAKE2b(msg="paseto-encryption-key" || n, key=key, len=56)
    # Ek = tmp[0:32], n2 = tmp[32:56]
    tmp = Blake2.hash2b("paseto-encryption-key" <> n, 56, key)
    <<ek::binary-32, n2::binary-24>> = tmp

    # Derive authentication key using BLAKE2b
    # Ak = BLAKE2b(msg="paseto-auth-key-for-aead" || n, key=key, len=32)
    ak = Blake2.hash2b("paseto-auth-key-for-aead" <> n, 32, key)

    # Encrypt with XChaCha20 (stream cipher, not AEAD)
    ciphertext = Crypto.xchacha20_encrypt(ek, data, n2)

    # Calculate BLAKE2b-MAC over PAE
    pre_auth = Utils.pre_auth_encode([@header_local, n, ciphertext, footer, implicit_assertion])
    mac = Crypto.blake2b_mac(ak, pre_auth, 32)

    Utils.b64_encode_token(@header_local, n <> ciphertext <> mac, footer)
  rescue
    _ -> {:error, "AEAD Encryption failed."}
  end

  @spec aead_decrypt(String.t(), binary, String.t(), String.t()) ::
          {:ok, String.t()} | {:error, String.t()}
  defp aead_decrypt(_data, key, _footer, _implicit_assertion)
       when byte_size(key) != @key_len do
    {:error, "Invalid key length. Expected #{@key_len}, but got #{byte_size(key)}"}
  end

  defp aead_decrypt(data, key, footer, implicit_assertion) when byte_size(key) == @key_len do
    decoded_payload = b64_decode!(data)
    decoded_footer = b64_decode!(footer)

    # Extract nonce (32 bytes), ciphertext, and MAC (32 bytes)
    mac_size = 32
    <<nonce::binary-size(@nonce_len), rest::binary>> = decoded_payload
    ciphertext_len = byte_size(rest) - mac_size
    <<ciphertext::binary-size(ciphertext_len), mac::binary-size(mac_size)>> = rest

    # Derive keys same as encryption
    tmp = Blake2.hash2b("paseto-encryption-key" <> nonce, 56, key)
    <<ek::binary-32, n2::binary-24>> = tmp

    ak = Blake2.hash2b("paseto-auth-key-for-aead" <> nonce, 32, key)

    # Verify MAC using constant-time comparison
    pre_auth = Utils.pre_auth_encode([@header_local, nonce, ciphertext, decoded_footer, implicit_assertion])
    expected_mac = Crypto.blake2b_mac(ak, pre_auth, 32)

    if :crypto.hash_equals(expected_mac, mac) do
      # Decrypt with XChaCha20
      plaintext = Crypto.xchacha20_decrypt(ek, ciphertext, n2)
      {:ok, plaintext}
    else
      {:error, "Authentication tag mismatch"}
    end
  end
end
