require 'omniauth-oauth2'
require 'json'
require 'net/http'
require 'atproto_client'
require 'didkit'
require 'faraday'

module OmniAuth
  module Strategies
    class Atproto < OmniAuth::Strategies::OAuth2
      # A failed login, with the key to fail the strategy with
      class LoginError < OmniAuth::Error
        attr_reader :key

        def initialize(key, message)
          super(message)
          @key = key
        end
      end

      option :fields, %i[handle]
      option :scope, 'atproto'
      option :pkce, true

      uid { @access_token.params['sub'] }

      info do
        {
          did: @access_token.params['sub'],
          nickname: verified_handle,
          pds_host: options.client_options.site
        }
      end

      # The handle can be posted in the form or the query string
      def request_phase
        handle = request.params['handle'].to_s.strip.delete_prefix('@')
        authorization_info = discover_authorization_server(handle)
        session['authorization_info'] = authorization_info
        use_authorization_server(authorization_info)
        # Lets the authorization server preselect the account
        options.authorize_params[:login_hint] = handle
        super
      rescue LoginError => e
        fail!(e.key, e)
      end

      def callback_phase
        authorization_info = session.delete('authorization_info')
        return fail!(:missing_authorization_info, OmniAuth::Error.new('No authorization request in progress')) unless authorization_info

        # The response has to come from the server the request went to (RFC 9207)
        issuer = authorization_info['issuer']
        raise LoginError.new(:issuer_mismatch, "Callback is from #{request.params['iss'].inspect}, not #{issuer}") unless request.params['iss'] == issuer

        @expected_did = authorization_info['did']
        use_authorization_server(authorization_info)
        super
      rescue LoginError => e
        fail!(e.key, e)
      end

      # The redirect_uri has to match the client metadata exactly, so leave off the query string
      def callback_url
        full_host + callback_path
      end

    private

      def build_access_token
        response = AtProto::Client.new(private_key: options.private_key).get_token!(
          **token_params.merge({
                                 code: request.params['code'],
                                 jwk: options.client_jwk,
                                 client_id: options.client_id,
                                 redirect_uri: callback_url,
                                 site: options.client_options.site,
                                 endpoint: options.client_options.token_url
                               }).to_h.transform_keys(&:to_sym)
        )
        # The token has to be for the account the handle resolved to
        raise LoginError.new(:did_mismatch, "Token is for #{response['sub'].inspect}, not #{@expected_did}") unless response['sub'] == @expected_did

        ::OAuth2::AccessToken.from_hash(client, response)
      end

      # The handle the DID claims, if it resolves back to the DID. The user may have
      # signed in to a different account than the handle they typed.
      def verified_handle
        @verified_handle ||= DIDKit::Resolver.new.get_verified_handle(@access_token.params['sub'])
      rescue StandardError
        nil
      end

      def discover_authorization_server(handle)
        raise LoginError.new(:missing_handle, 'Handle parameter is missing') if handle.empty?

        did, pds_endpoint = discovery_step(:unknown_handle) { resolve_pds(handle) }
        issuer = discovery_step(:invalid_auth_server) { get_authorization_server(pds_endpoint) }
        discovery_step(:invalid_metadata) { get_authorization_data(issuer) }.merge('did' => did)
      end

      # Discovery follows documents from user input, so any failure fails the login
      def discovery_step(key)
        yield
      rescue StandardError => e
        raise LoginError.new(key, e.message)
      end

      def use_authorization_server(authorization_info)
        options.client_options.site = authorization_info['issuer']
        options.client_options.authorize_url = authorization_info['authorization_endpoint']
        options.client_options.token_url = authorization_info['token_endpoint']
      end

      # The handle's DID, and the PDS it's hosted on
      def resolve_pds(handle)
        resolver = DIDKit::Resolver.new
        did = resolver.resolve_handle(handle)
        raise OmniAuth::Error.new('Handle parameter did not resolve to a did') unless did

        pds_endpoint = resolver.resolve_did(did).pds_endpoint
        raise OmniAuth::Error.new('DID document has no PDS endpoint') unless pds_endpoint

        [did.to_s, pds_endpoint]
      end

      def get_authorization_server(pds_endpoint)
        response = Faraday.get("#{pds_endpoint}/.well-known/oauth-protected-resource")
        raise OmniAuth::Error.new("Failed to get PDS authorization server: #{response.status}") unless response.success?

        JSON.parse(response.body).dig('authorization_servers', 0) or
          raise OmniAuth::Error.new('No authorization server found in response')
      end

      def get_authorization_data(issuer)
        response = Faraday.get("#{issuer}/.well-known/oauth-authorization-server")
        raise OmniAuth::Error.new("Failed to get authorization server metadata: #{response.status}") unless response.success?

        result = JSON.parse(response.body)
        raise OmniAuth::Error.new('Invalid metadata - issuer mismatch') unless result['issuer'] == issuer

        # we cannot keep everything in session (cookie overflow error)
        fields = %w[issuer authorization_endpoint token_endpoint]
        result.slice(*fields)
      end
    end
  end
end
