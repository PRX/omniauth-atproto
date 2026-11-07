require 'openssl'
require 'jwt'
require 'base64'

module OmniAuth
  module Atproto
    class KeyManager
      class << self
        KEY_PATH = 'config/atproto_private_key.pem'.freeze
        JWK_PATH = 'config/atproto_jwk.json'.freeze

        def generate_key_pair
          key = OpenSSL::PKey::EC.generate('prime256v1')
          private_key = key
          public_key = key.public_key

          # Get the coordinates for JWK
          # (not easy with openssl 3)
          bn = public_key.to_bn(:uncompressed)
          raw_bytes = bn.to_s(2)
          coord_bytes = raw_bytes[1..]
          byte_length = coord_bytes.length / 2

          x_coord = coord_bytes[0, byte_length]
          y_coord = coord_bytes[byte_length, byte_length]

          jwk = {
            kty: 'EC',
            crv: 'P-256',
            x: Base64.urlsafe_encode64(x_coord, padding: false),
            y: Base64.urlsafe_encode64(y_coord, padding: false),
            use: 'sig',
            alg: 'ES256',
            kid: SecureRandom.uuid
          }.freeze

          [private_key, jwk]
        end

        def current_private_key
          @current_private_key ||= load_or_generate_keys.first
        end

        def current_jwk
          @current_jwk ||= load_or_generate_keys.last
        end

        def rotate_keys
          # Backup current keys if they exist
          if File.exist?(KEY_PATH)
            File.write(KEY_PATH, 'config/old_atproto_private_key.pem')
            FileUtils.rm(KEY_PATH)
          end
          if File.exist?(JWK_PATH)
            File.write(JWK_PATH, 'config/old_atproto_jwk.json')
            FileUtils.rm(JWK_PATH)
          end
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
