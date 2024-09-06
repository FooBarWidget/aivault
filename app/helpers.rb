# frozen_string_literal: true
# typed: strict

require "sorbet-runtime"
require "uri"
require_relative "settings"

module DrivePlug
  module Helpers
    GOOGLE_DOC_MIME_TYPE_EXPORT_CONVERSIONS = T.let({
      "application/vnd.google-apps.document" => "text/x-markdown",
      "application/vnd.google-apps.spreadsheet" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
      "application/vnd.google-apps.presentation" => "application/vnd.openxmlformats-officedocument.presentationml.presentation"
    }, T::Hash[String, String])

    class << self
      extend T::Sig

      sig { params(orig_redirect_uri: String, gateway_code: String, origin_state: String).returns(String) }
      def extend_redirect_uri(orig_redirect_uri, gateway_code:, origin_state:)
        redirect_uri = URI.parse(orig_redirect_uri)
        query = (redirect_uri.query || "").dup
        query << "&" unless query.empty?
        query << URI.encode_www_form(
          code: gateway_code,
          state: origin_state
        )
        redirect_uri.query = query
        redirect_uri.to_s
      end

      sig { params(full_content: String).returns(String) }
      def extract_latest_journal_entry(full_content)
        full_content.split("\n---\n\n# Entry", 2).first || ""
      end

      sig { params(env: T::Hash[T.untyped, T.untyped], desc: String, token: T::Hash[String, T.untyped]).void }
      def log_auth_token(env, desc, token)
        return unless INSECURE_LOG_AUTH_TOKENS
        warn "Logging #{desc} authentication token"
        File.open("log/auth-tokens.log", "a:utf-8", perm: 0o600) do |f|
          f.puts("#{Time.now.utc.iso8601} #{env["PATH_INFO"]} #{desc}: #{token.to_json}")
        end
      rescue => e
        warn "Failed to log #{desc} authentication token: #{e}"
      end

      sig { params(token: OAuth2::AccessToken).returns(Integer) }
      def calculate_oauth2_token_expires_in(token)
        token.expires_in || [token.expires_at - Time.now.to_i, 0].max
      end
    end
  end
end
