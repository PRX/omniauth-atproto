require 'omniauth-oauth2'
require 'json'
require 'atproto_client'
require 'jwt'
require 'omniauth-atproto/safe_http'

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

      # The tokens are bound to this login's DPoP key, so apps that keep them need it too
      credentials { {'dpop_key' => @dpop_key.to_pem} }

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
        @dpop_key = OpenSSL::PKey::EC.generate('prime256v1')
        session['authorization_info'] = authorization_info.merge('dpop_key' => [@dpop_key.to_der].pack('m0'))
        use_authorization_server(authorization_info)
        # Lets the authorization server preselect the account
        options.authorize_params[:login_hint] = handle
        redirect pushed_authorization_url(authorization_info)
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
        @dpop_key = OpenSSL::PKey::EC.new(authorization_info['dpop_key'].unpack1('m0'))
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
        # The client key signs the client assertion, and this login's key the DPoP proofs
        atproto_client = AtProto::Client.new(private_key: options.private_key)
        atproto_client.dpop_handler = OmniAuth::Atproto::DpopHandler.new(@dpop_key)
        params = token_params.merge(
          code: request.params['code'],
          jwk: options.client_jwk,
          client_id: options.client_id,
          redirect_uri: callback_url,
          site: options.client_options.site,
          endpoint: options.client_options.token_url
        ).to_h.transform_keys(&:to_sym)
        response = login_step(:invalid_credentials) { atproto_client.get_token!(**params) }
        # The token has to be for the account the handle resolved to
        raise LoginError.new(:did_mismatch, "Token is for #{response['sub'].inspect}, not #{@expected_did}") unless response['sub'] == @expected_did

        ::OAuth2::AccessToken.from_hash(client, response)
      end

      # Pushes the authorization request to the server (PAR, which atproto requires),
      # so the browser only carries a reference to it
      def pushed_authorization_url(authorization_info)
        params = {response_type: 'code', client_id: options.client_id, redirect_uri: callback_url}.merge(authorize_params)
        response = login_step(:pushed_authorization_failed) do
          OmniAuth::Atproto::DpopHandler.new(@dpop_key).make_request(
            authorization_info['pushed_authorization_request_endpoint'],
            :post,
            headers: {'Content-Type' => 'application/x-www-form-urlencoded'},
            body: URI.encode_www_form(params.merge(client_assertion_params))
          )
        end
        request_uri = response['request_uri'] or raise LoginError.new(:pushed_authorization_failed, 'No request_uri in response')

        "#{options.client_options.authorize_url}?#{URI.encode_www_form(client_id: options.client_id, request_uri: request_uri)}"
      end

      # Authenticates this client with a JWT signed by its key (private_key_jwt)
      def client_assertion_params
        now = Time.now.to_i
        payload = {iss: options.client_id, sub: options.client_id, aud: options.client_options.site, jti: SecureRandom.uuid, iat: now, exp: now + 300}
        {
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
          client_assertion: JWT.encode(payload, options.private_key, 'ES256', {typ: 'jwt', kid: options.client_jwk[:kid]})
        }
      end

      # The handle the DID claims, if it resolves back to the DID. The user may have
      # signed in to a different account than the handle they typed.
      def verified_handle
        @verified_handle ||= OmniAuth::Atproto::Resolver.new.get_verified_handle(@access_token.params['sub'])
      rescue StandardError
        nil
      end

      def discover_authorization_server(handle)
        raise LoginError.new(:missing_handle, 'Handle parameter is missing') if handle.empty?

        did, pds_endpoint = login_step(:unknown_handle) { resolve_pds(handle) }
        issuer = login_step(:invalid_auth_server) { get_authorization_server(pds_endpoint) }
        login_step(:invalid_metadata) { get_authorization_data(issuer) }.merge('did' => did)
      end

      # Each step follows documents found from user input, so any failure fails the login
      def login_step(key)
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
        resolver = OmniAuth::Atproto::Resolver.new
        did = resolver.resolve_handle(handle)
        raise OmniAuth::Error.new('Handle parameter did not resolve to a did') unless did

        pds_endpoint = resolver.resolve_did(did).pds_endpoint
        raise OmniAuth::Error.new('DID document has no PDS endpoint') unless pds_endpoint

        [did.to_s, pds_endpoint]
      end

      def get_authorization_server(pds_endpoint)
        response = OmniAuth::Atproto::SafeHttp.request(:get, "#{pds_endpoint}/.well-known/oauth-protected-resource")
        raise OmniAuth::Error.new("Failed to get PDS authorization server: #{response.code}") unless response.is_a?(Net::HTTPSuccess)

        JSON.parse(response.body).dig('authorization_servers', 0) or
          raise OmniAuth::Error.new('No authorization server found in response')
      end

      def get_authorization_data(issuer)
        response = OmniAuth::Atproto::SafeHttp.request(:get, "#{issuer}/.well-known/oauth-authorization-server")
        raise OmniAuth::Error.new("Failed to get authorization server metadata: #{response.code}") unless response.is_a?(Net::HTTPSuccess)

        result = JSON.parse(response.body)
        raise OmniAuth::Error.new('Invalid metadata - issuer mismatch') unless result['issuer'] == issuer
        raise OmniAuth::Error.new('Invalid metadata - no pushed authorization request endpoint') unless result['pushed_authorization_request_endpoint']

        # we cannot keep everything in session (cookie overflow error)
        fields = %w[issuer authorization_endpoint token_endpoint pushed_authorization_request_endpoint]
        result.slice(*fields)
      end
    end
  end
end
