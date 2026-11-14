require 'json'
require 'atproto_client'
require 'didkit'
require 'ssrf_filter'

module OmniAuth
  module Atproto
    # HTTP for URLs that come from user input (handles, DID documents, server
    # metadata): public HTTPS addresses only, with timeouts and few redirects
    module SafeHttp
      HTTP_OPTIONS = {open_timeout: 5, read_timeout: 5}.freeze

      # Follows a few redirects for documents, and none for posts
      def self.request(method, url, headers: {}, body: nil)
        SsrfFilter.public_send(method, url, scheme_whitelist: %w[https], max_redirects: method == :get ? 3 : 0,
                                            http_options: HTTP_OPTIONS, headers: headers, body: body)
      end
    end

    # Resolves handles and DIDs with SafeHttp
    class Resolver < DIDKit::Resolver
    private

      def get_response(url, _options = {})
        SafeHttp.request(:get, url)
      end
    end

    # Sends DPoP requests with SafeHttp, retrying once with the server's nonce
    class DpopHandler < AtProto::DpopHandler
      def make_request(uri, method, headers: {}, body: nil)
        body = body.to_json if body.is_a?(Hash)
        2.times do
          dpop = generate_token(method.to_s.upcase, uri.to_s)
          request_headers = {'Content-Type' => 'application/json', 'Accept' => 'application/json'}.merge(headers, 'DPoP' => dpop)
          response = SafeHttp.request(method, uri, headers: request_headers, body: body)
          result = parse(response)
          return result if response.is_a?(Net::HTTPSuccess)
          # Keep only the OAuth error, since messages can end up in the flash
          raise AtProto::APIError.new("Request failed: #{response.code} #{result.values_at('error', 'error_description').compact.join(' - ')}") unless result['error'] == 'use_dpop_nonce'

          update_nonce(response)
        end
        raise AtProto::APIError.new('Request failed: server kept asking for a DPoP nonce')
      end

    private

      def parse(response)
        JSON.parse(response.body.to_s)
      rescue JSON::ParserError
        {}
      end
    end
  end
end
