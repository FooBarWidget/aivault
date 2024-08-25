# frozen_string_literal: true
# typed: strict

class GoogleToken < T::Struct
  extend T::Sig

  const :access_token, String
  const :refresh_token, T.nilable(String)
  const :expires_at, Integer
  const :token_type, String
  const :scope, T.nilable(String)

  sig { returns(T::Boolean) }
  def expired?
    Time.now.to_i > expires_at
  end

  sig { returns(Integer) }
  def expires_in
    expires_at - Time.now.to_i
  end
end
