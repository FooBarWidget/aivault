# frozen_string_literal: true
# typed: strict

require "sinatra/base"
require "oauth2"
require "securerandom"
require "json"
require "aws-sdk-kms"
require "sorbet-runtime"
require "google/apis/drive_v3"
require "googleauth"
require_relative "google_token"
require_relative "helpers"

class App < Sinatra::Base
  extend T::Sig

  BASE_URL = T.let(Helpers.require_env("BASE_URL"), String)
  ORIGIN_REDIRECT_URI = "https://chatgpt.com/aip/g-some_gpt_id/oauth/callback"
  ORIGIN_CLIENT_ID = T.let(Helpers.require_env("ORIGIN_CLIENT_ID"), String)
  ORIGIN_CLIENT_SECRET = T.let(Helpers.require_env("ORIGIN_CLIENT_SECRET"), String)
  GATEWAY_REDIRECT_URI = T.let("#{BASE_URL}/oauth2/callback", String)
  GOOGLE_CLIENT_ID = T.let(Helpers.require_env("GOOGLE_CLIENT_ID"), String)
  GOOGLE_CLIENT_SECRET = T.let(Helpers.require_env("GOOGLE_CLIENT_SECRET"), String)
  GOOGLE_OAUTH_SITE = "https://accounts.google.com"
  GOOGLE_TOKEN_URL = "/o/oauth2/token"
  GOOGLE_AUTHORIZE_URL = "/o/oauth2/auth"
  AWS_REGION = T.let(Helpers.require_env("AWS_REGION"), String)
  AWS_ACCESS_KEY_ID = T.let(Helpers.require_env("AWS_ACCESS_KEY_ID"), String)
  AWS_SECRET_ACCESS_KEY = T.let(Helpers.require_env("AWS_SECRET_ACCESS_KEY"), String)
  KMS_KEY_ID = T.let(Helpers.require_env("KMS_KEY_ID"), String)

  enable :sessions
  set :session_secret, ENV["SESSION_SECRET"] || SecureRandom.hex(64)

  configure do
    set :oauth_client, OAuth2::Client.new(
      GOOGLE_CLIENT_ID,
      GOOGLE_CLIENT_SECRET,
      site: GOOGLE_OAUTH_SITE,
      authorize_url: GOOGLE_AUTHORIZE_URL,
      token_url: GOOGLE_TOKEN_URL,
    )

    set :kms_client, Aws::KMS::Client.new(
      region: AWS_REGION,
      access_key_id: AWS_ACCESS_KEY_ID,
      secret_access_key: AWS_SECRET_ACCESS_KEY,
    )
  end

  get "/oauth2/authorize" do
    T.bind(self, App)
    content_type :json

    state = params[:state]
    client_id = params[:client_id]
    redirect_uri = params[:redirect_uri]

    if state.nil? || state.empty?
      status 400
      return { status: "error", message: "Missing state parameter." }.to_json
    end
    if client_id != ORIGIN_CLIENT_ID
      status 401
      return { status: "error", message: "Invalid client ID." }.to_json
    end
    if redirect_uri != ORIGIN_REDIRECT_URI
      status 400
      return { status: "error", message: "Invalid redirect URI." }.to_json
    end

    session[:origin_state] = state
    session[:gateway_state] = SecureRandom.urlsafe_base64(16)

    redirect settings.oauth_client.auth_code.authorize_url(
      redirect_uri: GATEWAY_REDIRECT_URI,
      scope: "https://www.googleapis.com/auth/drive",
      access_type: "offline",
      include_granted_scopes: "true",
      state: session[:gateway_state],
    )
  end

  get "/oauth2/callback" do
    T.bind(self, App)
    content_type :json

    google_code = params[:code]
    given_gateway_state = params[:state]
    expected_gateway_state = session.delete(:gateway_state)
    origin_state = session.delete(:origin_state)

    if google_code.nil? || given_gateway_state.nil?
      status 400
      return { status: "error", message: "Missing authorization code or state." }.to_json
    end
    if given_gateway_state != expected_gateway_state
      status 400
      return { status: "error", message: "Invalid state parameter." }.to_json
    end

    google_token = settings.oauth_client.auth_code.get_token(
      google_code,
      redirect_uri: GATEWAY_REDIRECT_URI,
    )
    google_token_struct = GoogleToken.from_hash(google_token.to_hash)
    encrypted_token = encrypt_token(google_token_struct.serialize.to_json)
    redirect build_origin_redirect_uri(encrypted_token, origin_state)
  end

  post "/oauth2/token" do
    T.bind(self, App)
    content_type :json

    if params[:client_id] != ORIGIN_CLIENT_ID || params[:client_secret] != ORIGIN_CLIENT_SECRET
      status 401
      return { status: "error", message: "Invalid client credentials." }.to_json
    end
    if params[:grant_type] != "authorization_code" && params[:grant_type] != "refresh_token"
      status 400
      return { status: "error", message: "Invalid grant type." }.to_json
    end

    case params[:grant_type]
    when "authorization_code"
      if params[:code].nil?
        status 400
        return { status: "error", message: "Missing authorization code." }.to_json
      end

      if params[:redirect_uri] != ORIGIN_REDIRECT_URI
        status 400
        return { status: "error", message: "Invalid redirect URI." }.to_json
      end

      encrypted_token = params[:code]
      google_token = GoogleToken.from_hash(JSON.parse(decrypt_token(encrypted_token)))
      refresh_token = encrypt_token(google_token.refresh_token.to_s)

      {
        access_token: encrypted_token,
        refresh_token: refresh_token,
        expires_in: google_token.expires_in,
        token_type: google_token.token_type,
      }.to_json
    when "refresh_token"
      encrypted_refresh_token = params[:refresh_token]
      decrypted_refresh_token = decrypt_token(encrypted_refresh_token)

      begin
        refreshed_token = settings.oauth_client.get_token(
          grant_type: "refresh_token",
          refresh_token: decrypted_refresh_token,
        )

        google_token = GoogleToken.from_hash(refreshed_token.to_hash)
        new_encrypted_token = encrypt_token(google_token.serialize.to_json)
        new_encrypted_refresh_token = encrypt_token(google_token.refresh_token.to_s)

        {
          access_token: new_encrypted_token,
          refresh_token: new_encrypted_refresh_token,
          expires_in: google_token.expires_in,
          token_type: google_token.token_type,
        }.to_json
      rescue OAuth2::Error => e
        if e.response.status == 401
          status 401
          { status: "error", message: "Invalid refresh token." }.to_json
        else
          raise e
        end
      end
    else
      raise "Bug: invalid grant type"
    end
  end

  post "/latest-journal" do
    T.bind(self, App)
    content_type :json
    encrypted_token = request.env["HTTP_AUTHORIZATION"].to_s.split(" ").last

    begin
      decrypted_token = JSON.parse(decrypt_token(encrypted_token))
      google_token = GoogleToken.from_hash(decrypted_token)

      if google_token.expired?
        refreshed_token = settings.oauth_client.get_token(
          grant_type: "refresh_token",
          refresh_token: google_token.refresh_token,
        )
        google_token = GoogleToken.from_hash(refreshed_token.to_hash)
        encrypted_token = encrypt_token(google_token.serialize.to_json)
      end

      drive_service = Google::Apis::DriveV3::DriveService.new
      drive_service.authorization = Google::Auth::UserRefreshCredentials.new(
        client_id: GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        scope: "https://www.googleapis.com/auth/drive",
        access_token: google_token.access_token,
        refresh_token: google_token.refresh_token,
        expires_at: google_token.expires_at,
      )

      journal_file = drive_service.list_files(q: "name = 'Journal' and mimeType = 'application/vnd.google-apps.document'", fields: "files(id, name)").files.first
      raise "Journal document not found" unless journal_file

      params = JSON.parse(request.body.read)
      text_to_prepend = params["text"]

      content = drive_service.export_file(journal_file.id, "text/plain")
      updated_content = "#{text_to_prepend}------\n#{content}"

      drive_service.update_file(
        journal_file.id,
        upload_source: StringIO.new(updated_content),
        content_type: "text/plain",
      )

      { status: "success", message: "Journal updated", new_token: encrypted_token }.to_json
    rescue => e
      status 500
      { status: "error", message: e.message }.to_json
    end
  end

  private

  sig { params(token_string: String).returns(String) }

  def encrypt_token(token_string)
    response = settings.kms_client.encrypt(
      key_id: KMS_KEY_ID,
      plaintext: token_string,
    )
    Base64.strict_encode64(response.ciphertext_blob)
  end

  sig { params(encrypted_token: String).returns(String) }

  def decrypt_token(encrypted_token)
    ciphertext_blob = Base64.strict_decode64(encrypted_token)
    response = settings.kms_client.decrypt(
      ciphertext_blob: ciphertext_blob,
      key_id: KMS_KEY_ID,
    )
    response.plaintext
  end

  sig { params(gateway_code: String, origin_state: String).returns(String) }

  def build_origin_redirect_uri(gateway_code, origin_state)
    redirect_uri = URI.parse(ORIGIN_REDIRECT_URI)
    query = (redirect_uri.query || "").dup
    query << "&" unless query.empty?
    query << URI.encode_www_form(
      code: gateway_code,
      state: origin_state,
    )
    redirect_uri.query = query
    redirect_uri.to_s
  end
end
