# frozen_string_literal: true
# typed: strict

module Helpers
  class << self
    extend T::Sig

    sig { params(name: String).returns(String) }

    def require_env(name)
      ENV[name] || raise("Missing environment variable: #{name}")
    end
  end
end
