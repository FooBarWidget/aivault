# frozen_string_literal: true
# typed: strict

require "aws-sdk-kms"
require "base64"
require_relative "base"
require_relative "../settings"

module DrivePlug
  module Kms
    class Aws < Base
      sig { void }
      def initialize
        @client = T.let(::Aws::KMS::Client.new(
          region: AWS_KMS_REGION,
          access_key_id: AWS_KMS_ACCESS_KEY_ID,
          secret_access_key: AWS_KMS_SECRET_ACCESS_KEY
        ), ::Aws::KMS::Client)
      end

      sig { override.params(plaintext: String).returns(String) }
      def encrypt(plaintext)
        response = @client.encrypt(
          key_id: AWS_KMS_KEY_ID,
          plaintext: plaintext
        )
        Base64.strict_encode64(response.ciphertext_blob)
      end

      sig { override.params(ciphertext: String).returns(String) }
      def decrypt(ciphertext)
        response = @client.decrypt(
          ciphertext_blob: Base64.decode64(ciphertext),
          key_id: AWS_KMS_KEY_ID
        )
        response.plaintext
      end
    end
  end
end
