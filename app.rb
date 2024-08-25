require "sinatra/base"
require "oauth2"
require "securerandom"
require "json"
require "dotenv/load"

class GoogleDriveApp < Sinatra::Base
  BASE_URL = ENV["BASE_URL"] || raise("Missing BASE_URL")
  ORIGIN_REDIRECT_URI = "https://chatgpt.com/aip/g-some_gpt_id/oauth/callback"
  ORIGIN_CLIENT_ID = ENV["ORIGIN_CLIENT_ID"] || raise("Missing ORIGIN_CLIENT_ID")
  ORIGIN_CLIENT_SECRET = ENV["ORIGIN_CLIENT_SECRET"] || raise("Missing ORIGIN_CLIENT_SECRET")
  GATEWAY_REDIRECT_URI = "#{BASE_URL}/oauth2/callback"
  GOOGLE_CLIENT_ID = ENV["GOOGLE_CLIENT_ID"] || raise("Missing GOOGLE_CLIENT_ID")
  GOOGLE_CLIENT_SECRET = ENV["GOOGLE_CLIENT_SECRET"] || raise("Missing GOOGLE_CLIENT_SECRET")
  GOOGLE_OAUTH_SITE = "https://accounts.google.com"
  GOOGLE_TOKEN_URL = "/o/oauth2/token"
  GOOGLE_AUTHORIZE_URL = "/o/oauth2/auth"

  GATEWAY_CODES = {}
  GATEWAY_CODE_MUTEX = Mutex.new
  GATEWAY_TOKENS = []
  GATEWAY_TOKENS_MUTEX = Mutex.new
  GATEWAY_CODE_EXPIRY = 3600 # 1 hour
  GATEWAY_TOKEN_EXPIRY = 3600 # 1 hour

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
  end

  before do
    cleanup_expired_tokens if rand < 0.1 # 10% chance to run cleanup on each request
  end

  get "/oauth2/authorize" do
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
    gateway_code = SecureRandom.hex(16)
    GATEWAY_CODE_MUTEX.synchronize do
      GATEWAY_CODES[gateway_code] = {
        google_token: google_token,
        expires_at: Time.now + GATEWAY_CODE_EXPIRY,
      }
    end

    redirect build_origin_redirect_uri(gateway_code, origin_state)
  end

  post "/oauth2/token" do
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

      gateway_code = GATEWAY_CODE_MUTEX.synchronize { GATEWAY_CODES.delete(params[:code]) }
      if gateway_code.nil?
        status 401
        return { status: "error", message: "Invalid authorization code." }.to_json
      end

      if gateway_code[:expires_at] < Time.now
        status 401
        return { status: "error", message: "Authorization code expired." }.to_json
      end

      gateway_token = {
        access_token: SecureRandom.urlsafe_base64(32),
        refresh_token: SecureRandom.urlsafe_base64(32),
        google_token: gateway_code[:google_token],
        expires_at: Time.now + GATEWAY_TOKEN_EXPIRY,
      }
      GATEWAY_TOKENS_MUTEX.synchronize { GATEWAY_TOKENS << gateway_token }

      {
        access_token: gateway_token[:access_token],
        refresh_token: gateway_token[:refresh_token],
        expires_in: GATEWAY_TOKEN_EXPIRY,
        token_type: "Bearer",
      }.to_json
    when "refresh_token"
      if params[:refresh_token].nil?
        status 400
        return { status: "error", message: "Missing refresh token." }.to_json
      end

      gateway_token = GATEWAY_TOKENS_MUTEX.synchronize { GATEWAY_TOKENS.find { |t| t[:refresh_token] == params[:refresh_token] } }
      if gateway_token.nil?
        status 401
        return { status: "error", message: "Invalid refresh token." }.to_json
      end

      if gateway_token[:expires_at] < Time.now
        GATEWAY_TOKENS_MUTEX.synchronize { GATEWAY_TOKENS.delete(gateway_token) }
        status 401
        return { status: "error", message: "Refresh token expired." }.to_json
      end

      begin
        gateway_token[:google_token].refresh!
        GATEWAY_TOKENS_MUTEX.synchronize do
          gateway_token[:access_token] = SecureRandom.urlsafe_base64(32)
          gateway_token[:expires_at] = Time.now + GATEWAY_TOKEN_EXPIRY
        end

        {
          access_token: gateway_token[:access_token],
          refresh_token: gateway_token[:refresh_token],
          expires_in: GATEWAY_TOKEN_EXPIRY,
          token_type: "Bearer",
        }.to_json
      rescue OAuth2::Error => e
        if e.response.status == 401
          GATEWAY_TOKENS_MUTEX.synchronize { GATEWAY_TOKENS.delete(gateway_token) }
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
    content_type :json
    gateway_access_token = request.env["HTTP_AUTHORIZATION"].to_s.split(" ").last
    google_token = GATEWAY_TOKENS_MUTEX.synchronize { GATEWAY_TOKENS.find { |t| t[:access_token] == gateway_access_token }&.dig(:google_token) }

    if google_token.nil?
      status 401
      return { status: "error", message: "Invalid access token" }.to_json
    end

    if google_token.expired?
      google_token = google_token.refresh!
      GATEWAY_TOKENS_MUTEX.synchronize do
        token_entry = GATEWAY_TOKENS.find { |t| t[:access_token] == gateway_access_token }
        token_entry[:google_token] = google_token if token_entry
      end
    end

    begin
      session = GoogleDrive::Session.from_access_token(google_token.token)

      journal_doc = session.files(q: "name = 'Journal' and mimeType = 'application/vnd.google-apps.document'").first
      raise "Journal document not found" unless journal_doc

      params = JSON.parse(request.body.read)
      text_to_prepend = params["text"]

      content = journal_doc.export_as_string("text/plain")
      updated_content = "#{text_to_prepend}------\n#{content}"
      journal_doc.update_from_string(updated_content, content_type: "text/plain")

      { status: "success", message: "Journal updated" }.to_json
    rescue => e
      status 500
      { status: "error", message: e.message }.to_json
    end
  end

  def cleanup_expired_tokens
    current_time = Time.now.to_i
    GATEWAY_CODE_MUTEX.synchronize { GATEWAY_CODES.delete_if { |_, entry| entry[:expires_at] < current_time } }
    GATEWAY_TOKENS_MUTEX.synchronize { GATEWAY_TOKENS.delete_if { |entry| entry[:expires_at] < current_time } }
  end

  def build_origin_redirect_uri(gateway_code, origin_state)
    redirect_uri = URI.parse(ORIGIN_REDIRECT_URI)
    redirect_uri.query = "" if redirect_uri.query.nil?
    redirect_uri.query += "&" unless redirect_uri.query.empty?
    redirect_uri.query += URI.encode_www_form(
      code: gateway_code,
      state: origin_state,
    )
    redirect_uri.to_s
  end
end
