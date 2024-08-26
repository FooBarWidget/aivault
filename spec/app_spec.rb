# frozen_string_literal: true
# typed: true

require "rspec"
require "rack/test"
require_relative "../app/app"

RSpec.describe AIMemoryGateway::App do
  T.bind(self, T.class_of(RSpec::ExampleGroups::AIMemoryGatewayApp))
  include Rack::Test::Methods

  T::Sig::WithoutRuntime.sig { returns(T.class_of(AIMemoryGateway::App)) }

  def app
    AIMemoryGateway::App
  end

  let(:mock_kms) { instance_double("Kms::Base") }
  let(:mock_oauth_client) { instance_double("OAuth2::Client") }

  before do
    app.set :raise_errors, true
    allow(app.settings).to receive(:kms).and_return(mock_kms)
    allow(app.settings).to receive(:oauth_client).and_return(mock_oauth_client)
  end

  describe "GET /oauth2/authorize" do
    it "redirects to Google OAuth with correct parameters" do
      state = "test_state"
      mock_auth_code = instance_double("OAuth2::Strategy::AuthCode")
      allow(mock_oauth_client).to receive(:auth_code).and_return(mock_auth_code)
      allow(mock_auth_code).to receive(:authorize_url).and_return("https://accounts.google.com/o/oauth2/auth?redirect_uri=...")

      get "/oauth2/authorize", {
        state: state,
        client_id: AIMemoryGateway::ORIGIN_CLIENT_ID,
        redirect_uri: AIMemoryGateway::ORIGIN_REDIRECT_URI,
      }

      expect(last_response).to be_redirect
      expect(last_response.location).to start_with("https://accounts.google.com/o/oauth2/auth")
    end

    it "returns an error for missing state" do
      get "/oauth2/authorize", {
        client_id: AIMemoryGateway::ORIGIN_CLIENT_ID,
        redirect_uri: AIMemoryGateway::ORIGIN_REDIRECT_URI,
      }

      expect(last_response.status).to eq(400)
      expect(JSON.parse(last_response.body)["message"]).to eq("Missing state parameter.")
    end

    # Add more tests for invalid client_id and redirect_uri
  end

  describe "GET /oauth2/callback" do
    it "handles successful callback and redirects" do
      session = { gateway_state: "test_gateway_state", origin_state: "test_origin_state" }
      allow_any_instance_of(AIMemoryGateway::App).to receive(:session).and_return(session)

      mock_token = instance_double(
        "OAuth2::AccessToken",
        to_hash: {
          "access_token" => "test_token",
          "expires_at" => 3600,
          "token_type" => "Bearer",
        },
      )
      mock_auth_code = instance_double("OAuth2::Strategy::AuthCode")
      allow(mock_oauth_client).to receive(:auth_code).and_return(mock_auth_code)
      allow(mock_oauth_client.auth_code).to receive(:get_token).and_return(mock_token)
      allow(mock_kms).to receive(:encrypt).and_return("encrypted_token")

      get "/oauth2/callback", { code: "test_code", state: "test_gateway_state" }

      expect(last_response).to be_redirect
      expect(last_response.location).to include(AIMemoryGateway::ORIGIN_REDIRECT_URI)
      expect(last_response.location).to include("encrypted_token")
    end

    it "returns an error for invalid state" do
      session = { gateway_state: "correct_state", origin_state: "test_origin_state" }
      allow_any_instance_of(AIMemoryGateway::App).to receive(:session).and_return(session)

      get "/oauth2/callback", { code: "test_code", state: "wrong_state" }

      expect(last_response.status).to eq(400)
      expect(JSON.parse(last_response.body)["message"]).to eq("Invalid state parameter.")
    end

    # Add more tests for missing code or state
  end

  describe "POST /oauth2/token" do
    context "with grant_type authorization_code" do
      it "exchanges authorization code for tokens" do
        allow(mock_kms).to receive(:decrypt).and_return('{"access_token":"test_access_token","refresh_token":"test_refresh_token","expires_at":0,"token_type":"Bearer"}')
        allow(mock_kms).to receive(:encrypt).and_return("encrypted_refresh_token")

        post "/oauth2/token", {
          grant_type: "authorization_code",
          code: "encrypted_auth_code",
          client_id: AIMemoryGateway::ORIGIN_CLIENT_ID,
          client_secret: AIMemoryGateway::ORIGIN_CLIENT_SECRET,
          redirect_uri: AIMemoryGateway::ORIGIN_REDIRECT_URI,
        }

        expect(last_response).to be_ok
        response_body = JSON.parse(last_response.body)
        expect(response_body["access_token"]).to eq("encrypted_auth_code")
        expect(response_body["refresh_token"]).to eq("encrypted_refresh_token")
      end
    end

    context "with grant_type refresh_token" do
      it "refreshes the token" do
        allow(mock_kms).to receive(:decrypt).and_return("decrypted_refresh_token")
        allow(mock_oauth_client).to receive(:get_token).and_return(
          OAuth2::AccessToken.from_hash(mock_oauth_client, {
            "access_token" => "new_access_token",
            "refresh_token" => "new_refresh_token",
            "expires_at" => Time.now.to_i + 3600,
            "token_type" => "Bearer",
          })
        )
        allow(mock_kms).to receive(:encrypt).and_return("new_encrypted_token")

        post "/oauth2/token", {
          grant_type: "refresh_token",
          refresh_token: "encrypted_refresh_token",
          client_id: AIMemoryGateway::ORIGIN_CLIENT_ID,
          client_secret: AIMemoryGateway::ORIGIN_CLIENT_SECRET,
        }

        expect(last_response).to be_ok
        response_body = JSON.parse(last_response.body)
        expect(response_body["access_token"]).to eq("new_encrypted_token")
        expect(response_body["refresh_token"]).to eq("new_encrypted_token")
      end
    end

    it "returns an error for invalid client credentials" do
      post "/oauth2/token", {
        grant_type: "authorization_code",
        code: "test_code",
        client_id: "invalid_client_id",
        client_secret: "invalid_client_secret",
        redirect_uri: AIMemoryGateway::ORIGIN_REDIRECT_URI,
      }

      expect(last_response.status).to eq(401)
      expect(JSON.parse(last_response.body)["message"]).to eq("Invalid client credentials.")
    end

    # Add more tests for invalid grant types and missing parameters
  end
end
