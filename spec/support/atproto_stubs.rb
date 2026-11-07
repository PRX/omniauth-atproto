# Stubs the network side of an atproto login: handle -> DID -> PDS ->
# authorization server, plus the token endpoint.
module AtprotoStubs
  HANDLE = 'alice.example.com'.freeze
  DID = 'did:plc:aliceaaaaaaaaaaaaaaaaaaa'.freeze
  PDS = 'https://pds.example.com'.freeze
  ISSUER = 'https://auth.example.com'.freeze
  CLIENT_ID = 'https://app.example.com/oauth/client-metadata.json'.freeze

  def client_key_pair
    @client_key_pair ||= OmniAuth::Atproto::KeyManager.generate_key_pair
  end

  def stub_handle(handle: HANDLE, did: DID)
    allow_any_instance_of(DIDKit::Resolver).to receive(:resolve_handle_by_dns).and_return(nil)
    stub_request(:get, "https://#{handle}/.well-known/atproto-did").to_return(body: did)
  end

  def stub_did_document(did: DID, handle: HANDLE, pds: PDS)
    document = {
      id: did,
      alsoKnownAs: ["at://#{handle}"],
      service: [{id: '#atproto_pds', type: 'AtprotoPersonalDataServer', serviceEndpoint: pds}]
    }
    stub_request(:get, "https://plc.directory/#{did}").
      to_return(body: document.to_json, headers: {'Content-Type' => 'application/did+ld+json'})
  end

  def stub_protected_resource(pds: PDS, issuer: ISSUER)
    stub_request(:get, "#{pds}/.well-known/oauth-protected-resource").
      to_return(body: {resource: pds, authorization_servers: [issuer]}.to_json,
                headers: {'Content-Type' => 'application/json'})
  end

  def stub_authorization_server(issuer: ISSUER, metadata_issuer: issuer)
    metadata = {
      issuer: metadata_issuer,
      authorization_endpoint: "#{issuer}/oauth/authorize",
      token_endpoint: "#{issuer}/oauth/token",
      pushed_authorization_request_endpoint: "#{issuer}/oauth/par",
      require_pushed_authorization_requests: true
    }
    stub_request(:get, "#{issuer}/.well-known/oauth-authorization-server").
      to_return(body: metadata.to_json, headers: {'Content-Type' => 'application/json'})
  end

  def stub_discovery(**opts)
    stub_handle(**opts.slice(:handle, :did))
    stub_did_document(**opts.slice(:handle, :did, :pds))
    stub_protected_resource(**opts.slice(:pds, :issuer))
    stub_authorization_server(**opts.slice(:issuer))
  end

  def stub_token(issuer: ISSUER, sub: DID, scope: 'atproto')
    stub_request(:post, "#{issuer}/oauth/token").to_return(
      body: {access_token: 'access', refresh_token: 'refresh', token_type: 'DPoP',
              expires_in: 3600, scope: scope, sub: sub}.to_json,
      headers: {'Content-Type' => 'application/json'}
    )
  end
end
