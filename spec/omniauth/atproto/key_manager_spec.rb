require 'spec_helper'
require 'tmpdir'

RSpec.describe OmniAuth::Atproto::KeyManager do
  it 'loads a key from a PEM, with a public JWK whose kid is its thumbprint' do
    pem = OpenSSL::PKey::EC.generate('prime256v1').to_pem

    key, jwk = described_class.load_key_pair(pem)

    expect(key.to_pem).to eq(pem)
    expect(jwk).to include(kty: 'EC', crv: 'P-256', use: 'sig', alg: 'ES256')
    expect(jwk).not_to have_key(:d)
    expect(jwk[:kid]).to eq(JWT::JWK::Thumbprint.new(JWT::JWK.new(key)).to_s)
  end

  it 'generates a P-256 key pair' do
    key, jwk = described_class.generate_key_pair

    expect(key.group.curve_name).to eq('prime256v1')
    expect(jwk[:x]).to eq(JWT::JWK.new(key).export[:x])
  end

  it 'backs up the old key files when rotating' do
    Dir.mktmpdir do |dir|
      Dir.chdir(dir) do
        FileUtils.mkdir('config')
        described_class.send(:load_or_generate_keys)
        old_pem = File.read('config/atproto_private_key.pem')

        described_class.rotate_keys

        expect(File.read('config/old_atproto_private_key.pem')).to eq(old_pem)
        expect(File.read('config/atproto_private_key.pem')).not_to eq(old_pem)
      end
    end
  end
end
