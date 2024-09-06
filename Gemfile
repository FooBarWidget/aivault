source "https://rubygems.org"

gem "sinatra"
gem "oauth2"
gem "aws-sdk-kms"
gem "google-cloud-kms-v1"
gem "nokogiri"
gem "sorbet-runtime"
gem "google-apis-drive_v3"
gem "rack"
gem "rack-protection"
gem "puma"

group :development do
  gem "sorbet"
  gem "tapioca", require: false
  gem "rbi", "~> 0.1.14" # 0.2 seems to cause issues with Tapioca
  gem "pry"
  gem "sorbet-rspec", git: "https://github.com/FooBarWidget/sorbet-rspec.git"
end

group :development, :test do
  gem "standard"
  gem "rspec"
  gem "rspec-sorbet"
  gem "rack-test"
end
