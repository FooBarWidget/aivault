# frozen_string_literal: true
# typed: strict

require "sorbet-runtime"

module DrivePlug
  module Kms
    class Base
      extend T::Sig
      extend T::Helpers

      abstract!

      sig { abstract.params(plaintext: String).returns(String) }

      def encrypt(plaintext); end

      sig { abstract.params(ciphertext: String).returns(String) }

      def decrypt(ciphertext); end
    end
  end
end
