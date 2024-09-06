# frozen_string_literal: true
# typed: strict

require "sorbet-runtime"
require "uri"
require_relative "settings"

module DrivePlug
  module Helpers
    GOOGLE_DOC_MIME_TYPE_EXPORT_CONVERSIONS = T.let({
      "application/vnd.google-apps.document" => "text/x-markdown",
      "application/vnd.google-apps.spreadsheet" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
      "application/vnd.google-apps.presentation" => "application/vnd.openxmlformats-officedocument.presentationml.presentation"
    }, T::Hash[String, String])

    class FileHierarchyEntry < T::Struct
      const :path, String
      const :file, Google::Apis::DriveV3::File
    end

    class << self
      extend T::Sig

      sig { params(orig_redirect_uri: String, gateway_code: String, origin_state: String).returns(String) }
      def extend_redirect_uri(orig_redirect_uri, gateway_code:, origin_state:)
        redirect_uri = URI.parse(orig_redirect_uri)
        query = (redirect_uri.query || "").dup
        query << "&" unless query.empty?
        query << URI.encode_www_form(
          code: gateway_code,
          state: origin_state
        )
        redirect_uri.query = query
        redirect_uri.to_s
      end

      sig { params(full_content: String).returns(String) }
      def extract_latest_journal_entry(full_content)
        full_content.split("\n---\n\n# Entry", 2).first || ""
      end

      sig { params(env: T::Hash[T.untyped, T.untyped], desc: String, creds: T::Hash[String, T.untyped]).void }
      def log_credentials(env, desc, creds)
        return unless INSECURE_LOG_CREDENTIALS
        warn "Logging #{desc} credentials"
        File.open("log/credentials.log", "a:utf-8", perm: 0o600) do |f|
          f.puts("#{Time.now.utc.iso8601} #{env["PATH_INFO"]} #{desc}: #{creds.to_json}")
        end
      rescue => e
        warn "Failed to log #{desc} credential: #{e}"
      end

      sig { params(token: OAuth2::AccessToken).returns(Integer) }
      def calculate_creds_expires_in(token)
        token.expires_in || [token.expires_at - Time.now.to_i, 0].max
      end

      sig { params(service: Google::Apis::DriveV3::DriveService, folder_id: String).returns(T::Array[FileHierarchyEntry]) }
      def list_files_recursively(service, folder_id)
        files = T.let([], T::Array[FileHierarchyEntry])
        page_token = T.let(nil, T.nilable(String))

        loop do
          response = service.list_files(
            q: "'#{escape folder_id}' in parents and trashed = false",
            fields: "nextPageToken, files(id, name, mimeType, parents)",
            page_token: page_token
          )
          files.concat(collect_files_and_subfolders(service, response.files, ""))
          page_token = response.next_page_token
          break if page_token.nil?
        end

        files
      end

      sig { params(service: Google::Apis::DriveV3::DriveService, file: Google::Apis::DriveV3::File, folder_id: String).returns(T::Boolean) }
      def file_under_folder?(service, file, folder_id)
        current_file = file
        while current_file.parents && !current_file.parents.empty?
          return true if current_file.parents.include?(folder_id)
          current_file = T.cast(service.get_file(current_file.parents.first, fields: "id, parents"), Google::Apis::DriveV3::File)
        end
        false
      end

      sig { params(gdrive_name: String).returns(String) }
      def escape(gdrive_name)
        gdrive_name.gsub("'", "\\'")
      end

      private

      sig { params(service: Google::Apis::DriveV3::DriveService, files: T::Array[Google::Apis::DriveV3::File], parent_path: String).returns(T::Array[FileHierarchyEntry]) }
      def collect_files_and_subfolders(service, files, parent_path)
        result = T.let([], T::Array[FileHierarchyEntry])
        files.each do |file|
          path = parent_path.empty? ? file.name : "#{parent_path}/#{file.name}"
          result << FileHierarchyEntry.new(path: path, file: file)
          if file.mime_type == "application/vnd.google-apps.folder"
            result.concat(collect_files_and_subfolders(service, list_files_in_folder(service, file.id), path))
          end
        end
        result
      end

      sig { params(service: Google::Apis::DriveV3::DriveService, folder_id: String).returns(T::Array[Google::Apis::DriveV3::File]) }
      def list_files_in_folder(service, folder_id)
        service.list_files(
          q: "'#{escape folder_id}' in parents and trashed = false",
          fields: "files(id, name, mimeType, parents)"
        ).files
      end
    end
  end
end
