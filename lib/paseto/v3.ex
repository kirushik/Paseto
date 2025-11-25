defmodule Paseto.V3 do
  @moduledoc """
  The Version3 implementation of the Paseto protocol.

  More information about the implementation can be found here:
  1.) https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version3.md

  v3 uses NIST-approved modern cryptography:
  - v3.local: AES-256-CTR + HMAC-SHA384 with HKDF key derivation
  - v3.public: ECDSA over P-384 curve with SHA-384

  This version is designed for environments that require NIST/FIPS compliance.
  """

  @behaviour Paseto.VersionBehaviour

  alias Paseto.Token
  alias Paseto.Utils
  alias Paseto.Utils.Crypto, as: PasetoCrypto

  import Paseto.Utils, only: [b64_decode: 1, b64_decode!: 1]

  @required_keys [:version, :purpose, :payload]
  @all_keys @required_keys ++ [:footer]

  @enforce_keys @all_keys
  defstruct @all_keys

  @header_public "v3.public."
  @header_local "v3.local."

  @hash_algo :sha384

  @nonce_size 32
  @mac_size 48
  # ECDSA P-384 signature is 96 bytes (r || s)
  @signature_size 96

  @doc """
  Takes a token and will decrypt/verify the signature and return the token in a more digestable manner
  """
  @spec from_token(Token.t()) :: %__MODULE__{}
  def from_token(token) do
    %__MODULE__{
      version: token.version,
      purpose: token.purpose,
      payload: token.payload,
      footer: token.footer
    }
  end

  @doc """
  Handles encrypting the payload and returning a valid token.

  v3.local uses:
  - AES-256-CTR for encryption
  - HMAC-SHA384 for authentication
  - HKDF-HMAC-SHA384 for key derivation

  # Examples:
      iex> key = :crypto.strong_rand_bytes(32)
      iex> Paseto.V3.encrypt("This is a test message", key)
      "v3.local...."
  """
  @spec encrypt(String.t(), binary, String.t(), String.t(), binary | nil) ::
          String.t() | {:error, String.t()}
  def encrypt(data, secret_key, footer \\ "", implicit_assertion \\ "", n \\ nil) do
    aead_encrypt(
      data,
      secret_key,
      footer,
      implicit_assertion,
      n || :crypto.strong_rand_bytes(@nonce_size)
    )
  end

  @doc """
  Handles decrypting a token payload given the correct key.

  Note: This function expects the base64-encoded payload (without the version header),
  not the full token string. Use `Paseto.Utils.parse_token/1` to extract the payload
  from a complete token.

  # Examples:
      iex> key = :crypto.strong_rand_bytes(32)
      iex> token = Paseto.V3.encrypt("This is a test message", key)
      iex> {:ok, %Paseto.Token{payload: payload}} = Paseto.Utils.parse_token(token)
      iex> Paseto.V3.decrypt(payload, key)
      {:ok, "This is a test message"}
  """
  @spec decrypt(String.t(), binary, String.t(), String.t()) ::
          {:ok, String.t()} | {:error, String.t()}
  def decrypt(data, secret_key, footer \\ "", implicit_assertion \\ "") do
    aead_decrypt(data, @header_local, secret_key, footer, implicit_assertion)
  end

  @doc """
  Handles signing the token for public use using ECDSA P-384.

  # Examples:
      iex> {public_key, private_key} = :crypto.generate_key(:ecdh, :secp384r1)
      iex> Paseto.V3.sign("This is a test message!", private_key)
      "v3.public...."
  """
  @spec sign(String.t(), binary, String.t(), String.t()) :: String.t() | {:error, String.t()}
  def sign(data, secret_key, footer \\ "", implicit_assertion \\ "") do
    # For v3.public, we need to include the compressed public key in the PAE
    # Derive public key from secret key
    {public_key, _} = :crypto.generate_key(:ecdh, :secp384r1, secret_key)

    # Compress the public key (should be 49 bytes: 0x02/0x03 + 48 bytes)
    compressed_pk = compress_public_key(public_key)

    m2 = Utils.pre_auth_encode([compressed_pk, @header_public, data, footer, implicit_assertion])

    # Sign using ECDSA P-384 with SHA-384
    # Erlang returns DER-encoded signature, we need raw r||s format
    der_signature = :crypto.sign(:ecdsa, @hash_algo, m2, [secret_key, :secp384r1])
    raw_signature = der_to_raw_signature(der_signature, 48)

    Utils.b64_encode_token(@header_public, data <> raw_signature, footer)
  rescue
    e in ArgumentError -> {:error, "Invalid signing key: #{inspect(e)}"}
    e in MatchError -> {:error, "Failed to parse signature format: #{inspect(e)}"}
    e -> {:error, "Signing failure: #{inspect(e)}"}
  end

  @doc """
  Handles verifying the signature belongs to the provided key.

  # Examples:
      iex> {public_key, secret_key} = :crypto.generate_key(:ecdh, :secp384r1)
      iex> token = Paseto.V3.sign("This is a test message!", secret_key)
      iex> {:ok, %Paseto.Token{payload: payload}} = Paseto.Utils.parse_token(token)
      iex> Paseto.V3.verify(payload, public_key)
      {:ok, "This is a test message!"}
  """
  @spec verify(String.t(), binary, String.t(), String.t()) ::
          {:ok, binary} | {:error, binary()}
  def verify(signed_message, public_key, footer \\ "", implicit_assertion \\ "") do
    decoded_footer = b64_decode!(footer)
    decoded_message = b64_decode!(signed_message)
    message_size = byte_size(decoded_message) - @signature_size

    <<
      message::binary-size(message_size),
      signature::binary-size(@signature_size)
    >> = decoded_message

    # Compress the public key for PAE
    compressed_pk = compress_public_key(public_key)

    m2 =
      Utils.pre_auth_encode([
        compressed_pk,
        @header_public,
        message,
        decoded_footer,
        implicit_assertion
      ])

    # Convert raw r||s signature to DER format for Erlang's :crypto.verify
    der_signature = raw_to_der_signature(signature, 48)

    case :crypto.verify(:ecdsa, @hash_algo, m2, der_signature, [public_key, :secp384r1]) do
      true -> {:ok, message}
      false -> {:error, "Failed to verify signature."}
    end
  rescue
    e in ArgumentError -> {:error, "Invalid key or signature format: #{inspect(e)}"}
    _e -> {:error, "Failed to verify signature."}
  end

  @spec get_claims_from_signed_message(signed_message :: String.t()) :: String.t()
  defp get_claims_from_signed_message(signed_message) do
    decoded = b64_decode!(signed_message)
    message_size = byte_size(decoded) - @signature_size

    <<
      message::binary-size(message_size),
      _signature::binary-size(@signature_size)
    >> = decoded

    message
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

  @spec aead_encrypt(String.t(), binary, String.t(), String.t(), binary) :: String.t()
  defp aead_encrypt(plaintext, key, footer, implicit_assertion, n) do
    # Derive encryption key and authentication key using HKDF
    # tmp = HKDF-HMAC-SHA384(len=48, ikm=key, info="paseto-encryption-key" || n, salt=NULL)
    # Ek = tmp[0:32], n2 = tmp[32:48]
    # NOTE: nonce is concatenated to info, NOT used as salt (v3 spec differs from v1)
    tmp = HKDF.derive(@hash_algo, key, 48, "", "paseto-encryption-key" <> n)
    <<ek::binary-32, n2::binary-16>> = tmp

    # Ak = HKDF-HMAC-SHA384(len=48, ikm=key, info="paseto-auth-key-for-aead" || n, salt=NULL)
    ak = HKDF.derive(@hash_algo, key, 48, "", "paseto-auth-key-for-aead" <> n)

    # Encrypt with AES-256-CTR
    ciphertext = PasetoCrypto.aes_256_ctr_encrypt(ek, plaintext, n2)

    # Calculate HMAC-SHA384
    pre_auth_hash =
      [@header_local, n, ciphertext, footer, implicit_assertion]
      |> Utils.pre_auth_encode()
      |> (&PasetoCrypto.hmac_sha384(ak, &1)).()

    Utils.b64_encode_token(@header_local, n <> ciphertext <> pre_auth_hash, footer)
  end

  @spec aead_decrypt(String.t(), String.t(), binary, String.t(), String.t()) ::
          {:ok, String.t()} | {:error, String.t()}
  defp aead_decrypt(message, header, key, footer, implicit_assertion) do
    expected_len = String.length(header)
    given_header = String.slice(message, 0..(expected_len - 1))

    with {:ok, decoded} <- b64_decode(message),
         {:ok, decoded_footer} <- b64_decode(footer) do
      aead_decrypt_inner(decoded, decoded_footer, header, key, implicit_assertion)
    else
      :error -> {:error, "Failed to decode header #{given_header} during decryption"}
      {:error, reason} -> {:error, reason}
    end
  end

  @spec aead_decrypt_inner(binary, binary, String.t(), binary, String.t()) ::
          {:ok, String.t()} | {:error, String.t()}
  defp aead_decrypt_inner(decoded, decoded_footer, header, key, implicit_assertion) do
    length = byte_size(decoded)
    ciphertext_len = length - @nonce_size - @mac_size

    <<
      nonce::binary-size(@nonce_size),
      ciphertext::binary-size(ciphertext_len),
      mac::binary-48
    >> = decoded

    # Derive keys same as encryption
    # NOTE: nonce is concatenated to info, NOT used as salt (v3 spec differs from v1)
    tmp = HKDF.derive(@hash_algo, key, 48, "", "paseto-encryption-key" <> nonce)
    <<ek::binary-32, n2::binary-16>> = tmp

    ak = HKDF.derive(@hash_algo, key, 48, "", "paseto-auth-key-for-aead" <> nonce)

    # Calculate expected MAC
    calc =
      [header, nonce, ciphertext, decoded_footer, implicit_assertion]
      |> Utils.pre_auth_encode()
      |> (&PasetoCrypto.hmac_sha384(ak, &1)).()

    # Use constant-time comparison
    if :crypto.hash_equals(calc, mac) do
      {:ok, PasetoCrypto.aes_256_ctr_decrypt(ek, ciphertext, n2)}
    else
      {:error, "Calculated hmac didn't match hmac from token."}
    end
  rescue
    e in ArgumentError -> {:error, "Invalid token format: #{inspect(e)}"}
    e -> {:error, "Decryption failed: #{inspect(e)}"}
  end

  # Convert DER-encoded ECDSA signature to raw r||s format
  # DER format: 0x30 <len> 0x02 <r_len> <r_bytes> 0x02 <s_len> <s_bytes>
  # Raw format: <r_bytes (48)> <s_bytes (48)> for P-384
  @spec der_to_raw_signature(binary, non_neg_integer) :: binary
  defp der_to_raw_signature(der_sig, coordinate_size) do
    # Parse DER sequence
    <<0x30, _seq_len, 0x02, r_len, r_data::binary>> = der_sig
    <<r_bytes::binary-size(r_len), 0x02, s_len, s_bytes::binary-size(s_len)>> = r_data

    # DER integers are signed, so they may have a leading 0x00 byte if the high bit is set
    # Also, they may be shorter than coordinate_size if there are leading zeros
    r = pad_or_trim_coordinate(r_bytes, coordinate_size)
    s = pad_or_trim_coordinate(s_bytes, coordinate_size)

    r <> s
  end

  # Convert raw r||s signature to DER format for Erlang's :crypto.verify
  @spec raw_to_der_signature(binary, non_neg_integer) :: binary
  defp raw_to_der_signature(raw_sig, coordinate_size) do
    <<r::binary-size(coordinate_size), s::binary-size(coordinate_size)>> = raw_sig

    # Remove leading zeros and add 0x00 if high bit is set (DER integer encoding)
    r_bytes = encode_der_integer(r)
    s_bytes = encode_der_integer(s)

    r_len = byte_size(r_bytes)
    s_len = byte_size(s_bytes)
    seq_len = 2 + r_len + 2 + s_len

    <<0x30, seq_len, 0x02, r_len>> <> r_bytes <> <<0x02, s_len>> <> s_bytes
  end

  # Pad coordinate to required size (add leading zeros) or trim leading 0x00 byte
  @spec pad_or_trim_coordinate(binary, non_neg_integer) :: binary
  defp pad_or_trim_coordinate(bytes, target_size) do
    case byte_size(bytes) do
      size when size == target_size ->
        bytes

      size when size == target_size + 1 ->
        # DER adds leading 0x00 for positive integers with high bit set
        <<0x00, rest::binary>> = bytes
        rest

      size when size < target_size ->
        # Pad with leading zeros
        padding = :binary.copy(<<0x00>>, target_size - size)
        padding <> bytes

      size ->
        raise ArgumentError,
              "Invalid coordinate size: #{size} bytes (expected at most #{target_size + 1} bytes)"
    end
  end

  # Encode a coordinate as a DER integer
  @spec encode_der_integer(binary) :: binary
  defp encode_der_integer(bytes) do
    # Remove leading zeros, but keep at least one byte
    trimmed = trim_leading_zeros(bytes)

    # Add leading 0x00 if high bit is set (to keep number positive in DER)
    <<high_bit::1, _::bitstring>> = trimmed

    if high_bit == 1 do
      <<0x00>> <> trimmed
    else
      trimmed
    end
  end

  # Remove leading zero bytes but keep at least one byte
  @spec trim_leading_zeros(binary) :: binary
  defp trim_leading_zeros(<<0x00, rest::binary>>) when byte_size(rest) > 0 do
    trim_leading_zeros(rest)
  end

  defp trim_leading_zeros(bytes), do: bytes

  # Compress an EC public key to 49 bytes (0x02/0x03 prefix + 48-byte X coordinate)
  # The prefix is 0x02 if Y is even, 0x03 if Y is odd
  @spec compress_public_key(binary) :: binary
  defp compress_public_key(<<0x04, x::binary-48, y::binary-48>>) do
    # Check if Y is even or odd (look at last bit of last byte)
    <<_::binary-47, last_byte>> = y
    prefix = if rem(last_byte, 2) == 0, do: 0x02, else: 0x03

    <<prefix, x::binary-48>>
  end

  defp compress_public_key(key) when byte_size(key) == 49 do
    # Already compressed
    key
  end

  defp compress_public_key(key) do
    raise ArgumentError,
          "Invalid public key format: expected 97 bytes (uncompressed) or 49 bytes (compressed), got #{byte_size(key)} bytes"
  end
end
