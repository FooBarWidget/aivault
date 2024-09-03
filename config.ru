# frozen_string_literal: true
# typed: strict

require "sorbet-runtime"
require "rack/protection"
require_relative "app/app"
require_relative "app/rack_conditional_protection"

ENV["RACK_ENV"] ||= "development"
T.bind(self, Rack::Builder)

use Rack::Static, urls: ["/css", "/js", "/images"], root: "public"
use Rack::CommonLogger
use Rack::Protection::FrameOptions
use Rack::Protection::HttpOrigin
use Rack::Protection::IPSpoofing
use Rack::Protection::JsonCsrf, allow_if: lambda { |env| env["PATH_INFO"] == "/oauth2/authorize" }
use Rack::Protection::PathTraversal
use DrivePlug::RackConditionalProtection, unprotected_paths: ["/oauth2/authorize"], middleware: Rack::Protection::RemoteToken
use Rack::Protection::XSSHeader

run DrivePlug::App
