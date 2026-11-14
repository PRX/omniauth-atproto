# Omniauth-atproto

An OmniAuth strategy for signing in with an AT Protocol account: Bluesky, Blacksky, or any other PDS. It follows the [atproto OAuth spec](https://atproto.com/specs/oauth): it finds the account's authorization server from the handle, pushes the authorization request (PAR), uses PKCE and DPoP, and authenticates as a confidential client with `private_key_jwt`.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'omniauth-atproto'
```

## Usage

### Keys

The client signs its requests with an ES256 (P-256) key. Generate one:

```bash
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out atproto_private_key.pem
```

and load it, from an environment variable or secret store, say:

```ruby
private_key, client_jwk = OmniAuth::Atproto::KeyManager.load_key_pair(ENV.fetch("ATPROTO_PRIVATE_KEY"))
```

`KeyManager.current_private_key` and `KeyManager.current_jwk` instead keep the key in `config/atproto_private_key.pem` and `config/atproto_jwk.json`, generating them if needed, and `KeyManager.rotate_keys` replaces them.

### Provider

The client ID is the https URL of your client metadata:

```ruby
Rails.application.config.middleware.use OmniAuth::Builder do
  provider :atproto,
    "https://example.com/oauth/client-metadata.json",
    nil,
    scope: "atproto",
    private_key: private_key,
    client_jwk: client_jwk
end
```

### Client metadata

Authorization servers fetch the client metadata from the client ID URL, so serve it there as JSON:

```ruby
OmniAuth::Atproto::MetadataGenerator.generate(
  client_id: "https://example.com/oauth/client-metadata.json",
  client_name: "Example",
  client_uri: "https://example.com",
  redirect_uri: "https://example.com/auth/atproto/callback",
  scope: "atproto",
  client_jwk: client_jwk
)
```

The scope and redirect URI have to match the provider's. The URL has to be public https, so in development use a tunnel like ngrok.

### Sign in form

Post the user's handle to the request phase, as a form field or in the query string. A leading `@` is fine. OmniAuth 2 only accepts POST here, so in Rails add [omniauth-rails_csrf_protection](https://github.com/cookpad/omniauth-rails_csrf_protection).

```erb
<%= form_tag("/auth/atproto", method: "post", data: {turbo: false}) do %>
  <%= text_field_tag :handle, nil, placeholder: "you.bsky.social" %>
  <%= submit_tag "Sign in with Bluesky" %>
<% end %>
```

The handle is required: the strategy uses it to find the authorization server, and checks the token is for that handle's account.

### Auth hash

- `uid`: the account's DID, which unlike the handle doesn't change
- `info.did`: the DID
- `info.nickname`: the handle, when it resolves back to the DID
- `info.pds_host`: the PDS that hosts the account, and its API
- `info.issuer`: the authorization server
- `info.scope`: the granted scope
- `credentials.token`, `credentials.refresh_token`, `credentials.expires_at`
- `credentials.dpop_key`: a PEM of the key the tokens are bound to. Requests with the tokens need DPoP proofs signed with it, so keep it with them, encrypted. [atproto-ruby](https://github.com/lasercatspro/atproto-ruby) can make those requests.

### Failures

A failed login goes to OmniAuth's failure endpoint with one of these messages:

- `missing_handle`: no handle was given
- `unknown_handle`: the handle, its DID document or its PDS couldn't be resolved
- `invalid_auth_server`: the PDS didn't name a usable authorization server
- `invalid_metadata`: the authorization server's metadata couldn't be fetched, has the wrong issuer, or has no PAR endpoint
- `pushed_authorization_failed`: the authorization server rejected the pushed request
- `missing_authorization_info`: a callback came with no sign in in progress
- `issuer_mismatch`: the callback's `iss` isn't the authorization server the request went to
- `invalid_credentials`: the token request failed
- `invalid_scope`: the token doesn't grant `atproto`
- `did_mismatch`: the token is for a different account than the handle's

### Security

Discovery, PAR and token requests follow URLs that come from user input, so they only go to public addresses over https, with short timeouts. Each sign in gets its own DPoP key. The callback has to come from the authorization server the request went to, and the token has to be for the DID the handle resolved to.

## Development

```bash
bundle install
bundle exec rake   # specs and RuboCop
```
