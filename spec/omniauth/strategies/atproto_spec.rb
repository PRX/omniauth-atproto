require 'spec_helper'

RSpec.describe OmniAuth::Strategies::Atproto do
  let(:app) do
    key, jwk = client_key_pair
    client_id = AtprotoStubs::CLIENT_ID
    Rack::Builder.new do
      use Rack::Session::Cookie, secret: 'x' * 64
      use OmniAuth::Strategies::Atproto, client_id, nil, scope: 'atproto', private_key: key, client_jwk: jwk
      run ->(env) { [200, {'content-type' => 'application/json'}, [env['omniauth.auth'].to_h.to_json]] }
    end
  end

  def redirect_params
    URI.decode_www_form(URI(last_response.location).query.to_s).to_h
  end

  def sign_in(handle: AtprotoStubs::HANDLE, iss: AtprotoStubs::ISSUER)
    post '/auth/atproto', handle: handle
    state = pushed_params['state']
    get '/auth/atproto/callback', code: 'auth-code', state: state, iss: iss
  end

  def failure_message
    expect(last_response.location).to start_with('/auth/failure')
    redirect_params['message']
  end

  describe 'request phase' do
    before { stub_discovery }

    it "pushes the authorization request (PAR) to the handle's authorization server" do
      post '/auth/atproto', handle: AtprotoStubs::HANDLE

      expect(pushed_params).to include(
        'client_id' => AtprotoStubs::CLIENT_ID,
        'redirect_uri' => 'https://app.example.com/auth/atproto/callback',
        'response_type' => 'code',
        'scope' => 'atproto',
        'code_challenge_method' => 'S256',
        'login_hint' => AtprotoStubs::HANDLE,
        'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
      )
      expect(pushed_params.values_at('state', 'code_challenge', 'client_assertion')).to all(match(/\S/))
      expect(a_request(:post, "#{AtprotoStubs::ISSUER}/oauth/par").with(headers: {'Dpop' => /\A[\w-]+\.[\w-]+\.[\w-]+\z/})).to have_been_made
    end

    it 'redirects with only the client_id and request_uri' do
      post '/auth/atproto', handle: AtprotoStubs::HANDLE

      expect(last_response.status).to eq(302)
      expect(last_response.location).to start_with("#{AtprotoStubs::ISSUER}/oauth/authorize?")
      expect(redirect_params).to eq('client_id' => AtprotoStubs::CLIENT_ID, 'request_uri' => AtprotoStubs::REQUEST_URI)
    end

    it 'retries the push with the DPoP nonce the server asks for' do
      stub_par(nonce: 'server-nonce')

      post '/auth/atproto', handle: AtprotoStubs::HANDLE

      expect(redirect_params['request_uri']).to eq(AtprotoStubs::REQUEST_URI)
      expect(a_request(:post, "#{AtprotoStubs::ISSUER}/oauth/par").with do |req|
        JWT.decode(req.headers['Dpop'], nil, false).first['nonce'] == 'server-nonce'
      end).to have_been_made
    end

    it 'fails cleanly when the push is rejected' do
      stub_request(:post, "#{AtprotoStubs::ISSUER}/oauth/par").
        to_return(status: 400, body: {error: 'invalid_client'}.to_json, headers: {'Content-Type' => 'application/json'})

      post '/auth/atproto', handle: AtprotoStubs::HANDLE

      expect(failure_message).to eq('pushed_authorization_failed')
    end

    it 'reads the handle from the query string, leaving it out of the redirect_uri' do
      post "/auth/atproto?handle=#{AtprotoStubs::HANDLE}"

      expect(last_response.location).to start_with("#{AtprotoStubs::ISSUER}/oauth/authorize?")
      expect(pushed_params['redirect_uri']).to eq('https://app.example.com/auth/atproto/callback')
    end

    it 'accepts a handle typed with a leading @' do
      post '/auth/atproto', handle: " @#{AtprotoStubs::HANDLE} "

      expect(last_response.location).to start_with("#{AtprotoStubs::ISSUER}/oauth/authorize?")
      expect(pushed_params['login_hint']).to eq(AtprotoStubs::HANDLE)
    end

    it 'fails cleanly without a handle' do
      post '/auth/atproto'

      expect(failure_message).to eq('missing_handle')
    end

    it 'fails cleanly when the handle does not resolve' do
      stub_request(:get, "https://#{AtprotoStubs::HANDLE}/.well-known/atproto-did").to_return(status: 404)

      post '/auth/atproto', handle: AtprotoStubs::HANDLE

      expect(failure_message).to eq('unknown_handle')
    end

    it 'fails cleanly when the PDS names no authorization server' do
      stub_protected_resource(authorization_servers: [])

      post '/auth/atproto', handle: AtprotoStubs::HANDLE

      expect(failure_message).to eq('invalid_auth_server')
    end

    it 'fails cleanly when the authorization server metadata has the wrong issuer' do
      stub_authorization_server(metadata_issuer: 'https://other.example.com')

      post '/auth/atproto', handle: AtprotoStubs::HANDLE

      expect(failure_message).to eq('invalid_metadata')
    end

    it 'refuses to fetch discovery documents from a private address' do
      stub_did_document(pds: 'https://169.254.169.254')

      post '/auth/atproto', handle: AtprotoStubs::HANDLE

      expect(failure_message).to eq('invalid_auth_server')
      expect(a_request(:get, /169\.254\.169\.254/)).not_to have_been_made
    end

    it 'refuses a handle whose host resolves to a private address' do
      allow(Resolv).to receive(:getaddresses).with(AtprotoStubs::HANDLE).and_return(['10.0.0.1'])

      post '/auth/atproto', handle: AtprotoStubs::HANDLE

      expect(failure_message).to eq('unknown_handle')
      expect(a_request(:get, "https://#{AtprotoStubs::HANDLE}/.well-known/atproto-did")).not_to have_been_made
    end

    it 'refuses a PDS without https' do
      stub_did_document(pds: 'http://pds.example.com')

      post '/auth/atproto', handle: AtprotoStubs::HANDLE

      expect(failure_message).to eq('invalid_auth_server')
    end
  end

  describe 'callback phase' do
    before { stub_discovery }

    it 'fails cleanly without a request phase first' do
      get '/auth/atproto/callback', code: 'auth-code', state: 'state'

      expect(failure_message).to eq('missing_authorization_info')
    end

    it 'exchanges the code at the token endpoint and returns the DID' do
      stub_token

      sign_in

      expect(last_response.status).to eq(200)
      auth = JSON.parse(last_response.body)
      expect(auth.dig('info', 'did')).to eq(AtprotoStubs::DID)
      expect(auth.dig('info', 'nickname')).to eq(AtprotoStubs::HANDLE)
      expect(auth['info']).to include('pds_host' => AtprotoStubs::PDS, 'issuer' => AtprotoStubs::ISSUER, 'scope' => 'atproto')
      expect(a_request(:post, "#{AtprotoStubs::ISSUER}/oauth/token").with do |req|
        body = JSON.parse(req.body)
        body['grant_type'] == 'authorization_code' && body['code'] == 'auth-code' &&
          body['code_verifier'] && body['client_assertion'] && req.headers['Dpop']
      end).to have_been_made
    end

    it "leaves out a handle that doesn't resolve back to the DID" do
      stub_token
      post '/auth/atproto', handle: AtprotoStubs::HANDLE
      state = pushed_params['state']
      # By the callback, the DID document's handle points at another account
      stub_request(:get, "https://#{AtprotoStubs::HANDLE}/.well-known/atproto-did").to_return(body: 'did:plc:malloryaaaaaaaaaaaaaaaaa')

      get '/auth/atproto/callback', code: 'auth-code', state: state, iss: AtprotoStubs::ISSUER

      expect(last_response.status).to eq(200)
      expect(JSON.parse(last_response.body).dig('info', 'nickname')).to be_nil
    end

    it 'sets the uid to the DID' do
      stub_token

      sign_in

      expect(JSON.parse(last_response.body)['uid']).to eq(AtprotoStubs::DID)
    end

    it 'fails cleanly when the token request is rejected' do
      stub_request(:post, "#{AtprotoStubs::ISSUER}/oauth/token").
        to_return(status: 400, body: {error: 'invalid_grant', error_description: 'Code expired'}.to_json, headers: {'Content-Type' => 'application/json'})

      sign_in

      expect(failure_message).to eq('invalid_credentials')
    end

    it 'rejects a token without the atproto scope' do
      stub_token(scope: 'transition:generic')

      sign_in

      expect(failure_message).to eq('invalid_scope')
    end

    it 'rejects a token whose sub is not the DID the handle resolved to' do
      stub_token(sub: 'did:plc:malloryaaaaaaaaaaaaaaaaa')

      sign_in

      expect(failure_message).to eq('did_mismatch')
    end

    it 'rejects a callback from a different issuer' do
      stub_token

      sign_in(iss: 'https://other.example.com')

      expect(failure_message).to eq('issuer_mismatch')
      expect(a_request(:post, "#{AtprotoStubs::ISSUER}/oauth/token")).not_to have_been_made
    end

    it 'rejects a callback without an issuer' do
      stub_token

      sign_in(iss: nil)

      expect(failure_message).to eq('issuer_mismatch')
    end

    def dpop_jwks(path)
      jwks = []
      expect(a_request(:post, "#{AtprotoStubs::ISSUER}/oauth/#{path}").with do |req|
        jwks << JWT.decode(req.headers['Dpop'], nil, false).last['jwk']
      end).to have_been_made.at_least_once
      jwks
    end

    it 'signs DPoP proofs with a per-login key, not the client key' do
      stub_token

      sign_in

      expect(dpop_jwks('token').first['x']).not_to eq(client_key_pair.last[:x])
    end

    it 'uses the same DPoP key for the push and the token request, and returns it' do
      stub_token

      sign_in

      token_jwk = dpop_jwks('token').first
      expect(dpop_jwks('par').first).to eq(token_jwk)
      dpop_key = OpenSSL::PKey::EC.new(JSON.parse(last_response.body).dig('credentials', 'dpop_key'))
      expect(JWT::JWK.new(dpop_key).export[:x]).to eq(token_jwk['x'])
    end

    it 'uses a different DPoP key for each login' do
      stub_token

      sign_in
      sign_in

      expect(dpop_jwks('token').uniq.size).to eq(2)
    end
  end
end
