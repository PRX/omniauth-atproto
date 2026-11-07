require 'simplecov'
SimpleCov.start do
  enable_coverage :branch
  add_filter '/spec/'
end

require 'omniauth-atproto'
require 'rack/test'
require 'rack/session'
require 'webmock/rspec'

Dir[File.join(__dir__, 'support', '**', '*.rb')].sort.each { |f| require f }

OmniAuth.config.logger = Logger.new(IO::NULL)
OmniAuth.config.request_validation_phase = nil
OmniAuth.config.full_host = 'https://app.example.com'

WebMock.disable_net_connect!

RSpec.configure do |config|
  config.include Rack::Test::Methods
  config.include AtprotoStubs

  config.expect_with :rspec do |expectations|
    expectations.include_chain_clauses_in_custom_matcher_descriptions = true
  end
  config.mock_with :rspec do |mocks|
    mocks.verify_partial_doubles = true
  end
  config.disable_monkey_patching!
  config.order = :random
end
