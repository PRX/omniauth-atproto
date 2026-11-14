require 'fileutils'
require 'json'
require 'openssl'
require 'jwt'

module OmniAuth
  module Atproto
    class KeyManager
      class << self
        KEY_PATH = 'config/atproto_private_key.pem'.freeze
        JWK_PATH = 'config/atproto_jwk.json'.freeze

        def generate_key_pair
          key = OpenSSL::PKey::EC.generate('prime256v1')
          [key, public_jwk(key)]
        end

        # Loads a key from a PEM (from an environment variable or secret store, say)
        def load_key_pair(pem)
          key = OpenSSL::PKey::EC.new(pem)
          [key, public_jwk(key)]
        end

        # The public key for the client metadata's jwks, with its thumbprint as the kid
        def public_jwk(key)
          JWT::JWK.new(key, {use: 'sig', alg: 'ES256'}, kid_generator: JWT::JWK::Thumbprint).export.freeze
        end

        def current_private_key
          @current_private_key ||= load_or_generate_keys.first
        end

        def current_jwk
          @current_jwk ||= load_or_generate_keys.last
        end

        def rotate_keys
          # Backup current keys if they exist
          FileUtils.mv(KEY_PATH, 'config/old_atproto_private_key.pem') if File.exist?(KEY_PATH)
          FileUtils.mv(JWK_PATH, 'config/old_atproto_jwk.json') if File.exist?(JWK_PATH)
          @current_private_key = @current_jwk = nil
          load_or_generate_keys
        end

      private

        def load_or_generate_keys
          if File.exist?(KEY_PATH) && File.exist?(JWK_PATH)
            private_key = OpenSSL::PKey::EC.new(File.read(KEY_PATH))
            jwk = JSON.parse(File.read(JWK_PATH), symbolize_names: true)
          else
            private_key, jwk = generate_key_pair
            File.write(KEY_PATH, private_key.to_pem)
            File.write(JWK_PATH, JSON.pretty_generate(jwk))
          end
          [private_key, jwk]
        end
      end
    end
  end
end
