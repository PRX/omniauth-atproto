require 'spec_helper'

RSpec.describe OmniAuth::Atproto::MetadataGenerator do
  it "defaults to the strategy's atproto scope" do
    metadata = described_class.generate(client_id: AtprotoStubs::CLIENT_ID, client_jwk: client_key_pair.last)

    expect(metadata[:scope]).to eq('atproto')
    expect(metadata[:jwks]).to eq(keys: [client_key_pair.last])
  end
end
