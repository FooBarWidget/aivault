# typed: true
# frozen_string_literal: true

require "aws-sdk-kms"
require "google/apis/drive_v3"
require "googleauth"
require "json"
require "oauth2"
require "securerandom"
require "sinatra/base"
require "sorbet-runtime"
