# typed: strict

class OAuth2::Client
  sig do
    params(
      params: T::Hash[T.untyped, T.untyped],
      access_token_opts: T::Hash[T.untyped, T.untyped],
      extract_access_token: T::Proc,
      block: T.nilable(T.proc.params(req: T.untyped).void)
    ).returns(OAuth2::AccessToken)
  end
  def get_token(params, access_token_opts = T.unsafe(nil), extract_access_token = T.unsafe(nil), &block)
  end
end

class OAuth2::AccessToken
  class << self
    sig { params(client: OAuth2::Client, hash: T::Hash[T.untyped, T.untyped]).returns(OAuth2::AccessToken) }
    def from_hash(client, hash)
    end
  end

  sig { returns(SnakyHash::StringKeyed) }
  def to_hash
  end
end
