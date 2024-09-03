# typed: strict

class RSpec::Core::ExampleGroup
  sig { returns(::RSpec::Matchers::DSL::Matcher) }

  def be_redirect; end

  sig { returns(::RSpec::Matchers::DSL::Matcher) }

  def be_ok; end
end
