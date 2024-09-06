# frozen_string_literal: true
# typed: true

require "rspec"
require "rspec/sorbet"
require "rack/test"
require "sorbet-runtime"
require_relative "../app/app"

RSpec::Sorbet.allow_instance_doubles!

# Workaround for https://github.com/sorbet/sorbet/issues/8143
if false
  T::Sig::WithoutRuntime.sig { params(block: T.proc.bind(T::Private::Methods::DeclBuilder).void).void }
  def sig(&block)
  end
end

RSpec.describe DrivePlug::App, "OAuth2" do
  T.bind(self, T.class_of(RSpec::ExampleGroups::DrivePlugAppOAuth2))
  extend T::Sig
  include Rack::Test::Methods

  sig { returns(T.class_of(DrivePlug::App)) }
  def app
    DrivePlug::App
  end

  let(:mock_kms) { instance_double("Kms::Base") }
  let(:mock_oauth_client) { instance_double("OAuth2::Client") }

  before do
    app.set :raise_errors, true
    app.set :show_exceptions, false
    allow(app.settings).to receive(:kms).and_return(mock_kms)
    allow(app.settings).to receive(:oauth_client).and_return(mock_oauth_client)
  end

  describe "GET /oauth2/authorize" do
    it "redirects to Google OAuth with correct parameters" do
      state = "test_state"
      mock_auth_code = instance_double("OAuth2::Strategy::AuthCode")
      expect(mock_oauth_client).to receive(:auth_code).and_return(mock_auth_code)
      expect(mock_auth_code).to receive(:authorize_url).and_return("https://accounts.google.com/o/oauth2/auth?redirect_uri=...")

      get "/oauth2/authorize", {
        state: state,
        client_id: DrivePlug::ORIGIN_CLIENT_ID,
        redirect_uri: DrivePlug::ORIGIN_REDIRECT_URI
      }

      expect(last_response).to be_redirect
      expect(last_response.location).to start_with("https://accounts.google.com/o/oauth2/auth")
    end

    it "returns an error for missing state" do
      get "/oauth2/authorize", {
        client_id: DrivePlug::ORIGIN_CLIENT_ID,
        redirect_uri: DrivePlug::ORIGIN_REDIRECT_URI
      }

      expect(last_response.status).to eq(400)
      expect(JSON.parse(last_response.body)["message"]).to eq("Missing state parameter.")
    end

    # Add more tests for invalid client_id and redirect_uri
  end

  describe "GET /oauth2/callback" do
    it "handles successful callback and redirects" do
      session = {gateway_state: "test_gateway_state", origin_state: "test_origin_state"}
      expect_any_instance_of(DrivePlug::App).to receive(:session).at_least(:once).and_return(session)

      mock_token = instance_double(
        "OAuth2::AccessToken",
        to_hash: {
          "access_token" => "test_token",
          "expires_at" => 3600,
          "token_type" => "Bearer"
        }
      )
      mock_auth_code = instance_double("OAuth2::Strategy::AuthCode")
      expect(mock_oauth_client).to receive(:auth_code).at_least(:once).and_return(mock_auth_code)
      expect(mock_oauth_client.auth_code).to receive(:get_token).and_return(mock_token)
      expect(mock_kms).to receive(:encrypt).and_return("encrypted_token")

      get "/oauth2/callback", {code: "test_code", state: "test_gateway_state"}

      expect(last_response).to be_redirect
      expect(last_response.location).to include(DrivePlug::ORIGIN_REDIRECT_URI)
      expect(last_response.location).to include("encrypted_token")
    end

    it "returns an error for invalid state" do
      session = {gateway_state: "correct_state", origin_state: "test_origin_state"}
      expect_any_instance_of(DrivePlug::App).to receive(:session).at_least(:once).and_return(session)

      get "/oauth2/callback", {code: "test_code", state: "wrong_state"}

      expect(last_response.status).to eq(400)
      expect(JSON.parse(last_response.body)["message"]).to eq("Invalid state parameter.")
    end

    # Add more tests for missing code or state
  end

  describe "POST /oauth2/token" do
    context "with grant_type authorization_code" do
      it "exchanges authorization code for tokens" do
        expect(mock_kms).to \
          receive(:decrypt)
          .with("encrypted_auth_code")
          .and_return('{"access_token":"test_access_token","refresh_token":"test_refresh_token","expires_at":0,"token_type":"Bearer"}')
        expect(mock_kms).to \
          receive(:encrypt)
          .with("test_refresh_token")
          .and_return("encrypted_refresh_token")

        post "/oauth2/token", {
          grant_type: "authorization_code",
          code: "encrypted_auth_code",
          client_id: DrivePlug::ORIGIN_CLIENT_ID,
          client_secret: DrivePlug::ORIGIN_CLIENT_SECRET,
          redirect_uri: DrivePlug::ORIGIN_REDIRECT_URI
        }

        expect(last_response).to be_ok
        response_body = JSON.parse(last_response.body)
        expect(response_body["access_token"]).to eq("encrypted_auth_code")
        expect(response_body["refresh_token"]).to eq("encrypted_refresh_token")
      end
    end

    context "with grant_type refresh_token" do
      it "refreshes the token" do
        google_token = OAuth2::AccessToken.from_hash(mock_oauth_client, {
          "access_token" => "new_access_token",
          "refresh_token" => "new_refresh_token",
          "expires_at" => Time.now.to_i + 3600,
          "token_type" => "Bearer"
        })
        expect(mock_kms).to \
          receive(:decrypt)
          .with("encrypted_refresh_token")
          .and_return("decrypted_refresh_token")
        expect(mock_oauth_client).to \
          receive(:get_token)
          .with(grant_type: "refresh_token", refresh_token: "decrypted_refresh_token")
          .and_return(google_token)
        expect(mock_kms).to \
          receive(:encrypt)
          .with(google_token.to_hash.to_json)
          .and_return("new_encrypted_token")
        expect(mock_kms).to \
          receive(:encrypt)
          .with("new_refresh_token")
          .and_return("new_encrypted_refresh_token")

        post "/oauth2/token", {
          grant_type: "refresh_token",
          refresh_token: "encrypted_refresh_token",
          client_id: DrivePlug::ORIGIN_CLIENT_ID,
          client_secret: DrivePlug::ORIGIN_CLIENT_SECRET
        }

        expect(last_response).to be_ok
        response_body = JSON.parse(last_response.body)
        expect(response_body["access_token"]).to eq("new_encrypted_token")
        expect(response_body["refresh_token"]).to eq("new_encrypted_refresh_token")
      end
    end

    it "returns an error for invalid client credentials" do
      post "/oauth2/token", {
        grant_type: "authorization_code",
        code: "test_code",
        client_id: "invalid_client_id",
        client_secret: "invalid_client_secret",
        redirect_uri: DrivePlug::ORIGIN_REDIRECT_URI
      }

      expect(last_response.status).to eq(401)
      expect(JSON.parse(last_response.body)["message"]).to eq("Invalid client credentials.")
    end

    # Add more tests for invalid grant types and missing parameters
  end
end
