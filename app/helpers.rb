# frozen_string_literal: true
# typed: strict

require "sorbet-runtime"
require "uri"
require_relative "settings"

module DrivePlug
  module Helpers
    class << self
      extend T::Sig

      sig { params(orig_redirect_uri: String, gateway_code: String, origin_state: String).returns(String) }

      def extend_redirect_uri(orig_redirect_uri, gateway_code, origin_state)
        redirect_uri = URI.parse(orig_redirect_uri)
        query = (redirect_uri.query || "").dup
        query << "&" unless query.empty?
        query << URI.encode_www_form(
          code: gateway_code,
          state: origin_state,
        )
        redirect_uri.query = query
        redirect_uri.to_s
      end
    end
  end
end
