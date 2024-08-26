# frozen_string_literal: true
# typed: strict

require "base64"
require "google/cloud/kms/v1/key_management_service"
require "google/cloud/kms/v1/key_management_service/client"
require_relative "base"
require_relative "../settings"

module AIMemoryGateway
  module Kms
    class Gcloud < Base
      sig { void }

      def initialize
        @client = T.let(Google::Cloud::Kms::V1::KeyManagementService::Client.new do |config|
          config = T.cast(config, Google::Cloud::Kms::V1::KeyManagementService::Client::Configuration)
          config.credentials = GCLOUD_KMS_CREDENTIALS_FILE
        end, Google::Cloud::Kms::V1::KeyManagementService::Client)
      end

      sig { override.params(plaintext: String).returns(String) }

      def encrypt(plaintext)
        name = @client.crypto_key_path(
          project: GCLOUD_KMS_PROJECT_ID,
          location: GCLOUD_KMS_KEY_RING_LOCATION,
          key_ring: GCLOUD_KMS_KEY_RING,
          crypto_key: GCLOUD_KMS_KEY_ID,
        )
        response = @client.encrypt(name: name, plaintext: plaintext)
        Base64.strict_encode64(response.ciphertext)
      end

      sig { override.params(ciphertext: String).returns(String) }

      def decrypt(ciphertext)
        name = @client.crypto_key_path(
          project: GCLOUD_KMS_PROJECT_ID,
          location: GCLOUD_KMS_KEY_RING_LOCATION,
          key_ring: GCLOUD_KMS_KEY_RING,
          crypto_key: GCLOUD_KMS_KEY_ID,
        )
        response = @client.decrypt(name: name, ciphertext: Base64.decode64(ciphertext))
        response.plaintext
      end
    end
  end
end
