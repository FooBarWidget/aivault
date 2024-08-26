# typed: strict

module RSpec
  class << self
    sig do
      params(
        args: T.untyped,
        example_group_block: T.proc.bind(T.class_of(RSpec::Core::ExampleGroup)).void,
      ).void
    end

    def describe(*args, &example_group_block); end
  end

  module Core
    class ExampleGroup
      class << self
        sig do
          params(
            all_args: T.untyped,
            block: T.proc.bind(RSpec::Mocks::ExampleMethods).void,
          ).void
        end

        def it(*all_args, &block); end

        sig do
          params(
            args: T.untyped,
            block: T.proc.bind(RSpec::Mocks::ExampleMethods).void,
          ).void
        end

        def before(*args, &block); end

        sig do
          params(
            args: T.untyped,
            block: T.proc.bind(RSpec::Mocks::ExampleMethods).void,
          ).void
        end

        def after(*args, &block); end
      end

      sig { returns(::RSpec::Matchers::DSL::Matcher) }

      def be_redirect; end

      sig { returns(::RSpec::Matchers::DSL::Matcher) }

      def be_ok; end
    end
  end
end
