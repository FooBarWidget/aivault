# frozen_string_literal: true
# typed: true

require "rspec/core"
require_relative "../../../spec/app_spec"

module Tapioca
  module Dsl
    module Compilers
      class RSpecCoreExampleGroup < Compiler
        extend T::Sig

        ConstantType = type_member { { fixed: T.class_of(::RSpec::Core::ExampleGroup) } }

        sig { override.returns(T::Enumerable[Module]) }
        def self.gather_constants
          all_classes.select { |c| c < ::RSpec::Core::ExampleGroup }
        end

        sig { override.void }

        def decorate
          klass = root.create_class(T.must(constant.name), superclass_name: T.must(constant.superclass).name)
          create_includes(klass)
          create_singleton_methods(klass)
          #create_instance_methods(klass)
        end

        private

        def create_includes(klass)
          if defined?(::RSpec::Matchers) && constant < ::RSpec::Matchers
            klass.create_include("::RSpec::Matchers")
          end
          if defined?(::RSpec::Mocks::ExampleMethods) && constant < ::RSpec::Mocks::ExampleMethods
            klass.create_include("::RSpec::Mocks::ExampleMethods")
          end

          directly_included_modules_for(constant).each do |included_mod|
            klass.create_include("::#{included_mod}")

            if included_mod.name&.start_with?("RSpec::ExampleGroups")
              mod = root.create_module(T.must(included_mod.name))
              direct_public_instance_methods_for(included_mod).each do |method_name|
                mod.create_method(
                  method_name.to_s,
                  parameters: parameters_for(included_mod, method_name),
                  return_type: "T.untyped",
                )
              end
            end
          end
        end

        def create_singleton_methods(klass)
          klass.create_class("<< self") do |singleton_class|
            singleton_class.create_method(
              "let",
              parameters: [
                create_rest_param("name", type: "T.untyped"),
                create_block_param("block", type: "T.proc.bind(#{constant.name}).void"),
              ],
            )

            singleton_class.create_method(
              "before",
              parameters: [
                create_rest_param("args", type: "T.untyped"),
                create_block_param("block", type: "T.proc.bind(#{constant.name}).void"),
              ],
            )

            singleton_class.create_method(
              "after",
              parameters: [
                create_rest_param("args", type: "T.untyped"),
                create_block_param("block", type: "T.proc.bind(#{constant.name}).void"),
              ],
            )

            singleton_class.create_method(
              "it",
              parameters: [
                create_rest_param("all_args", type: "T.untyped"),
                create_block_param("block", type: "T.proc.bind(#{constant.name}).void"),
              ],
            )

            singleton_class.create_method(
              "specify",
              parameters: [
                create_rest_param("all_args", type: "T.untyped"),
                create_block_param("block", type: "T.proc.bind(#{constant.name}).void"),
              ],
            )
          end
        end

        def create_instance_methods(klass)
          direct_public_instance_methods_for(constant).each do |method_name|
            klass.create_method(
              method_name.to_s,
              parameters: parameters_for(constant, method_name),
              return_type: "T.untyped",
            )
          end
        end

        sig { params(constant: Module).returns(T::Enumerable[Module]) }

        def directly_included_modules_for(constant)
          result = constant.included_modules
          result -= constant.included_modules.map do |included_mod|
            included_mod.ancestors - [included_mod]
          end.flatten
          if constant.is_a?(Class) && constant.superclass
            result -= T.must(constant.superclass).included_modules
          end
          result
        end

        sig { params(constant: Module).returns(T::Enumerable[Symbol]) }

        def direct_public_instance_methods_for(constant)
          result = constant.public_instance_methods
          constant.included_modules.each do |included_mod|
            result -= included_mod.public_instance_methods
          end
          if constant.is_a?(Class) && constant.superclass
            result -= T.must(constant.superclass).public_instance_methods
          end
          result
        end

        def parameters_for(constant, method_name)
          i = 0
          constant.instance_method(method_name).parameters.map do |type, name|
            i += 1
            name ||= "_arg#{i}"

            case type
            when :req
              create_param(name, type: "T.untyped")
            when :opt
              create_opt_param(name, type: "T.untyped", default: "T.unsafe(nil)")
            when :rest
              create_rest_param(name, type: "T.untyped")
            when :keyreq
              create_kw_param(name, type: "T.untyped")
            when :key
              create_kw_opt_param(name, type: "T.untyped", default: "T.unsafe(nil)")
            when :keyrest
              create_kw_rest_param("_arg#{i}", type: "T.untyped")
            when :block
              create_block_param(name, type: "T.untyped")
            else
              raise "Unsupported parameter type on #{constant}##{method_name}: #{[type, name].inspect}"
            end
          end
        end
      end
    end
  end
end
