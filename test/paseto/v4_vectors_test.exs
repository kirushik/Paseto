defmodule Paseto.V4VectorsTest do
  use ExUnit.Case, async: true

  alias Paseto.{Token, Utils, V4}

  @v4_vectors File.read!("test/fixtures/test_vectors/v4.json") |> Jason.decode!()

  describe "v4 test vectors" do
    @v4_vectors["tests"]
    |> Enum.each(fn test ->
      @test test
      test "#{@test["name"]}" do
        implicit_assertion = @test["implicit-assertion"] || ""

        cond do
          # Local (symmetric) test - has "key" field
          @test["key"] != nil ->
            run_local_test(@test, implicit_assertion)

          # Public (asymmetric) test - has "public-key" field
          @test["public-key"] != nil ->
            run_public_test(@test, implicit_assertion)

          true ->
            flunk("Unknown test type: #{@test["name"]}")
        end
      end
    end)
  end

  defp run_local_test(test, implicit_assertion) do
    key = Base.decode16!(test["key"], case: :lower)

    if test["expect-fail"] do
      {:ok, %Token{payload: encrypted_payload, footer: encoded_footer}} =
        Utils.parse_token(test["token"])

      result = V4.decrypt(encrypted_payload, key, encoded_footer, implicit_assertion)
      assert match?({:error, _}, result), "Expected decryption to fail but it succeeded"
    else
      nonce = Base.decode16!(test["nonce"], case: :lower)
      footer = test["footer"]

      # Test encryption produces expected token
      result = V4.encrypt(test["payload"], key, footer, implicit_assertion, nonce)

      assert result == test["token"], """
      Expected: #{test["token"]}
      Got:      #{result}
      """

      # Test decryption recovers original payload
      {:ok, %Token{payload: encrypted_payload, footer: encoded_footer}} =
        Utils.parse_token(test["token"])

      assert V4.decrypt(encrypted_payload, key, encoded_footer, implicit_assertion) ==
               {:ok, test["payload"]}
    end
  end

  defp run_public_test(test, implicit_assertion) do
    public_key = Base.decode16!(test["public-key"], case: :lower)

    if test["expect-fail"] do
      {:ok, %Token{payload: signed_payload, footer: encoded_footer}} =
        Utils.parse_token(test["token"])

      result = V4.verify(signed_payload, public_key, encoded_footer, implicit_assertion)
      assert match?({:error, _}, result), "Expected verification to fail but it succeeded"
    else
      secret_key = Base.decode16!(test["secret-key"], case: :lower)
      footer = test["footer"]

      # Test signing produces expected token
      result = V4.sign(test["payload"], secret_key, footer, implicit_assertion)

      assert result == test["token"], """
      Expected: #{test["token"]}
      Got:      #{result}
      """

      # Test verification succeeds
      {:ok, %Token{payload: signed_payload, footer: encoded_footer}} =
        Utils.parse_token(test["token"])

      assert V4.verify(signed_payload, public_key, encoded_footer, implicit_assertion) ==
               {:ok, test["payload"]}
    end
  end
end
