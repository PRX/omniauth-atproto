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
    state = redirect_params['state']
    get '/auth/atproto/callback', code: 'auth-code', state: state, iss: iss
  end

  def failure_message
    expect(last_response.location).to start_with('/auth/failure')
    redirect_params['message']
  end

  describe 'request phase' do
    before { stub_discovery }

    it "redirects to the authorization server of the handle's PDS" do
      post '/auth/atproto', handle: AtprotoStubs::HANDLE

      expect(last_response.status).to eq(302)
      expect(last_response.location).to start_with("#{AtprotoStubs::ISSUER}/oauth/authorize?")
      expect(redirect_params).to include(
        'client_id' => AtprotoStubs::CLIENT_ID,
        'redirect_uri' => 'https://app.example.com/auth/atproto/callback',
        'response_type' => 'code',
        'scope' => 'atproto',
        'code_challenge_method' => 'S256',
        'login_hint' => AtprotoStubs::HANDLE
      )
      expect(redirect_params['state']).not_to be_empty
      expect(redirect_params['code_challenge']).not_to be_empty
    end

    it 'reads the handle from the query string, leaving it out of the redirect_uri' do
      post "/auth/atproto?handle=#{AtprotoStubs::HANDLE}"

      expect(last_response.location).to start_with("#{AtprotoStubs::ISSUER}/oauth/authorize?")
      expect(redirect_params['redirect_uri']).to eq('https://app.example.com/auth/atproto/callback')
    end

    it 'accepts a handle typed with a leading @' do
      post '/auth/atproto', handle: " @#{AtprotoStubs::HANDLE} "

      expect(last_response.location).to start_with("#{AtprotoStubs::ISSUER}/oauth/authorize?")
      expect(redirect_params['login_hint']).to eq(AtprotoStubs::HANDLE)
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

    it 'pushes the authorization request (PAR) and redirects with its request_uri' do
      pending 'PAR is not implemented yet'
      stub_request(:post, "#{AtprotoStubs::ISSUER}/oauth/par").
        to_return(status: 201, body: {request_uri: 'urn:ietf:params:oauth:request_uri:abc', expires_in: 60}.to_json,
                  headers: {'Content-Type' => 'application/json'})

      post '/auth/atproto', handle: AtprotoStubs::HANDLE

      expect(redirect_params).to eq('client_id' => AtprotoStubs::CLIENT_ID,
                                    'request_uri' => 'urn:ietf:params:oauth:request_uri:abc')
    end

    it 'refuses to fetch discovery documents from a private address' do
      pending 'discovery is not SSRF-guarded yet'
      stub_did_document(pds: 'https://169.254.169.254')

      post '/auth/atproto', handle: AtprotoStubs::HANDLE

      expect(failure_message).to eq('invalid_auth_server')
      expect(a_request(:get, /169\.254\.169\.254/)).not_to have_been_made
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
      expect(a_request(:post, "#{AtprotoStubs::ISSUER}/oauth/token").with do |req|
        body = JSON.parse(req.body)
        body['grant_type'] == 'authorization_code' && body['code'] == 'auth-code' &&
          body['code_verifier'] && body['client_assertion'] && req.headers['Dpop']
      end).to have_been_made
    end

    it "leaves out a handle that doesn't resolve back to the DID" do
      stub_token
      post '/auth/atproto', handle: AtprotoStubs::HANDLE
      state = redirect_params['state']
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

    it 'rejects a token whose sub is not the DID the handle resolved to' do
      pending 'the token sub is not checked against the handle'
      stub_token(sub: 'did:plc:malloryaaaaaaaaaaaaaaaaa')

      sign_in

      expect(failure_message).to eq('did_mismatch')
    end

    it 'rejects a callback from a different issuer' do
      pending 'the iss callback parameter is not checked'
      stub_token

      sign_in(iss: 'https://other.example.com')

      expect(failure_message).to eq('issuer_mismatch')
    end

    it 'signs DPoP proofs with a per-login key, not the client key' do
      pending 'the client key is reused for DPoP'
      stub_token

      sign_in

      client_jwk = client_key_pair.last
      expect(a_request(:post, "#{AtprotoStubs::ISSUER}/oauth/token").with do |req|
        header = JWT.decode(req.headers['Dpop'], nil, false).last
        header.dig('jwk', 'x') != client_jwk[:x]
      end).to have_been_made
    end
  end
end
