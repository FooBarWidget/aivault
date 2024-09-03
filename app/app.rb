# frozen_string_literal: true
# typed: strict

require "sinatra/base"
require "oauth2"
require "securerandom"
require "json"
require "stringio"
require "time"
require "sorbet-runtime"
require "google/apis/drive_v3"
require "googleauth"
require_relative "settings"
require_relative "helpers"

module DrivePlug
  class App < Sinatra::Base
    extend T::Sig

    GATEWAY_REDIRECT_URI = T.let("#{BASE_URL}/oauth2/callback", String)
    GOOGLE_OAUTH_SITE = "https://accounts.google.com"
    GOOGLE_TOKEN_URL = "/o/oauth2/token"
    GOOGLE_AUTHORIZE_URL = "/o/oauth2/auth"

    enable :sessions
    set :session_secret, SESSION_SECRET

    configure do
      set :oauth_client, OAuth2::Client.new(
        GOOGLE_CLIENT_ID,
        GOOGLE_CLIENT_SECRET,
        site: GOOGLE_OAUTH_SITE,
        authorize_url: GOOGLE_AUTHORIZE_URL,
        token_url: GOOGLE_TOKEN_URL,
      )

      case KMS_TYPE
      when "aws"
        require_relative "kms/aws"
        set :kms, Kms::Aws.new
      when "gcloud"
        require_relative "kms/gcloud"
        set :kms, Kms::Gcloud.new
      else
        raise "Bug: invalid KMS type"
      end
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
      if client_id != DrivePlug::ORIGIN_CLIENT_ID
        status 401
        return { status: "error", message: "Invalid client ID." }.to_json
      end
      if redirect_uri != ORIGIN_REDIRECT_URI
        status 400
        return { status: "error", message: "Invalid redirect URI." }.to_json
      end

      session[:origin_state] = state
      session[:gateway_state] = SecureRandom.urlsafe_base64(16)

      redirect get_oauth_client.auth_code.authorize_url(
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

      google_token = get_oauth_client.auth_code.get_token(
        google_code,
        redirect_uri: GATEWAY_REDIRECT_URI,
      )
      encrypted_token = get_kms.encrypt(google_token.to_hash.to_json)
      redirect Helpers.extend_redirect_uri(ORIGIN_REDIRECT_URI, encrypted_token, origin_state)
    end

    post "/oauth2/token" do
      T.bind(self, App)
      content_type :json

      if params[:client_id] != DrivePlug::ORIGIN_CLIENT_ID || params[:client_secret] != DrivePlug::ORIGIN_CLIENT_SECRET
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
        google_token = OAuth2::AccessToken.from_hash(get_oauth_client, JSON.parse(get_kms.decrypt(encrypted_token)))
        refresh_token = get_kms.encrypt(google_token.refresh_token.to_s)

        {
          access_token: encrypted_token,
          refresh_token: refresh_token,
          expires_in: google_token.expires_in,
          token_type: "Bearer",
        }.to_json
      when "refresh_token"
        encrypted_refresh_token = params[:refresh_token]
        decrypted_refresh_token = get_kms.decrypt(encrypted_refresh_token)

        begin
          google_token = get_oauth_client.get_token(
            grant_type: "refresh_token",
            refresh_token: decrypted_refresh_token,
          )
          new_encrypted_token = get_kms.encrypt(google_token.to_hash.to_json)
          new_encrypted_refresh_token = get_kms.encrypt(google_token.refresh_token)

          {
            access_token: new_encrypted_token,
            refresh_token: new_encrypted_refresh_token,
            expires_in: google_token.expires_in,
            token_type: "Bearer",
          }.to_json
        rescue OAuth2::Error => e
          puts e
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

    get "/journal/latest.md" do
      T.bind(self, App)
      content_type :json

      drive_service = get_drive_service
      journal = drive_service.list_files(
        q: "name = '#{JOURNAL_DOCUMENT_NAME}' and mimeType = 'application/vnd.google-apps.document' and '#{GDRIVE_FOLDER_ID}' in parents and trashed = false",
        fields: "files(id, name)",
      ).files.first
      if journal.nil?
        content_type "text/x-markdown"
        return ""
      end

      journal_content = drive_service.export_file(journal.id, "text/x-markdown")
      content_type "text/x-markdown"
      Helpers.extract_latest_journal_entry(journal_content)
    end

    post "/journal/latest.md" do
      T.bind(self, App)
      content_type :json

      input_body = request.body.read
      if input_body.nil? || input_body.empty?
        status 400
        return { status: "error", message: "Missing request body." }.to_json
      end

      params = JSON.parse(input_body)
      text_to_prepend = params["text"]
      if text_to_prepend.nil? || text_to_prepend.empty?
        status 400
        return { status: "error", message: "Missing or empty text parameter." }.to_json
      end

      drive_service = get_drive_service
      journal = drive_service.list_files(
        q: "name = '#{JOURNAL_DOCUMENT_NAME}' and mimeType = 'application/vnd.google-apps.document' and '#{GDRIVE_FOLDER_ID}' in parents and trashed = false",
        fields: "files(id, name)",
      ).files.first

      if journal.nil?
        content = <<~EOF
          # Journal entry #{Time.now.iso8601}

          #{text_to_prepend}
        EOF

        drive_service.create_file(
          Google::Apis::DriveV3::File.new(
            name: JOURNAL_DOCUMENT_NAME,
            parents: [GDRIVE_FOLDER_ID],
            mime_type: "application/vnd.google-apps.document",
          ),
          upload_source: StringIO.new(content),
          content_type: "text/x-markdown",
        )
        { status: "success", message: "Journal created." }.to_json
      else
        existing_content = drive_service.export_file(journal.id, "text/x-markdown")
        updated_content = <<~EOF
          # Journal entry #{Time.now.iso8601}

          #{text_to_prepend}

          ---

          #{existing_content}
        EOF

        drive_service.update_file(
          journal.id,
          upload_source: StringIO.new(updated_content),
          content_type: "text/x-markdown",
        )
        status 201
        { status: "success", message: "Journal updated." }.to_json
      end
    end

    sig { returns(OAuth2::Client) }

    def get_oauth_client
      T.bind(self, App)
      settings.oauth_client
    end

    sig { returns(Kms::Base) }

    def get_kms
      T.bind(self, App)
      settings.kms
    end

    sig { returns(Google::Apis::DriveV3::DriveService) }

    def get_drive_service
      T.bind(self, App)

      if (auth_header = request.env["HTTP_AUTHORIZATION"]).nil?
        content_type :json
        halt 401, { status: "error", message: "Missing Authorization header" }.to_json
      end

      encrypted_token = auth_header.split(" ").last
      decrypted_token = JSON.parse(get_kms.decrypt(encrypted_token))
      oauth_client = get_oauth_client
      google_token = T.cast(OAuth2::AccessToken.from_hash(oauth_client, decrypted_token), OAuth2::AccessToken)

      drive_service = Google::Apis::DriveV3::DriveService.new
      drive_service.authorization = Google::Auth::UserRefreshCredentials.new(
        client_id: GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        scope: "https://www.googleapis.com/auth/drive",
        access_token: google_token.token,
        refresh_token: google_token.refresh_token,
        expires_at: google_token.expires_at,
      )

      drive_service
    end
  end
end
