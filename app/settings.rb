# frozen_string_literal: true
# typed: strict

require "securerandom"
require "sorbet-runtime"

module DrivePlug
  extend T::Sig

  sig { params(name: String).returns(String) }

  def self.require_env(name)
    ENV[name] || abort("Required environment variable: #{name}")
  end

  BASE_URL = T.let(require_env("BASE_URL"), String)
  ORIGIN_CLIENT_ID = T.let(require_env("ORIGIN_CLIENT_ID"), String)
  ORIGIN_CLIENT_SECRET = T.let(require_env("ORIGIN_CLIENT_SECRET"), String)
  ORIGIN_REDIRECT_URI = T.let(require_env("ORIGIN_REDIRECT_URI"), String)
  GOOGLE_CLIENT_ID = T.let(require_env("GOOGLE_CLIENT_ID"), String)
  GOOGLE_CLIENT_SECRET = T.let(require_env("GOOGLE_CLIENT_SECRET"), String)
  GDRIVE_FOLDER_ID = T.let(require_env("GDRIVE_FOLDER_ID"), String)
  JOURNAL_DOCUMENT_NAME = T.let(ENV["JOURNAL_DOCUMENT_NAME"] || "Journal", String)
  SESSION_SECRET = T.let(ENV["SESSION_SECRET"] || SecureRandom.hex(64), String)

  KMS_TYPE = T.let(require_env("KMS_TYPE"), String)

  case KMS_TYPE
  when "aws"
    AWS_KMS_REGION = T.let(require_env("AWS_KMS_REGION"), String)
    AWS_KMS_ACCESS_KEY_ID = T.let(require_env("AWS_KMS_ACCESS_KEY_ID"), String)
    AWS_KMS_SECRET_ACCESS_KEY = T.let(require_env("AWS_KMS_SECRET_ACCESS_KEY"), String)
    AWS_KMS_KEY_ID = T.let(require_env("AWS_KMS_KEY_ID"), String)
  when "gcloud"
    GCLOUD_KMS_PROJECT_ID = T.let(require_env("GCLOUD_KMS_PROJECT_ID"), String)
    GCLOUD_KMS_KEY_RING_LOCATION = T.let(require_env("GCLOUD_KMS_KEY_RING_LOCATION"), String)
    GCLOUD_KMS_KEY_RING = T.let(require_env("GCLOUD_KMS_KEY_RING"), String)
    GCLOUD_KMS_KEY_ID = T.let(require_env("GCLOUD_KMS_KEY_ID"), String)
    GCLOUD_KMS_CREDENTIALS_FILE = T.let(require_env("GCLOUD_KMS_CREDENTIALS_FILE"), String)
  else
    raise "Invalid KMS_TYPE: #{KMS_TYPE}. Must be 'aws' or 'gcloud'."
  end
end
