module OmniAuth
  module Atproto
    class MetadataGenerator
      def self.generate(options)
        {
          client_id: options[:client_id],
          application_type: 'web',
          client_name: options[:client_name],
          client_uri: options[:client_uri],
          dpop_bound_access_tokens: true,
          grant_types: %w[authorization_code refresh_token],
          redirect_uris: [options[:redirect_uri]],
          response_types: ['code'],
          scope: options[:scope] || 'atproto transition:generic',
          token_endpoint_auth_method: 'private_key_jwt',
          token_endpoint_auth_signing_alg: 'ES256',
          jwks: {
            keys: [options[:client_jwk]]
          }
        }
      end
    end
  end
end
