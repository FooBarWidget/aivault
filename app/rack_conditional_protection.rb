# frozen_string_literal: true
# typed: strict

module DrivePlug
  # A Rack middleware that only calls a sub-middleware if the request path is
  # not in a list of unprotected paths. Allows us to disable certain Rack::Protection middlewares
  # for certain paths only.
  class RackConditionalProtection
    extend T::Sig

    sig { params(app: T.untyped, unprotected_paths: T::Array[String], middleware: T.untyped).void }
    def initialize(app, unprotected_paths:, middleware:)
      @app = app
      @unprotected_paths = unprotected_paths
      @middleware = T.let(middleware.new(app), T.untyped)
    end

    sig { params(env: T.untyped).returns(T.untyped) }
    def call(env)
      path = env["PATH_INFO"]
      if @unprotected_paths.any? { |unprotected_path| path == unprotected_path }
        @app.call(env)
      else
        @middleware.call(env)
      end
    end
  end
end
