require 'simplecov'
SimpleCov.start :rails do
  add_filter "lib/jd_auth/version.rb"
end

ENV['RAILS_ENV'] ||= 'test'

require 'action_controller/railtie'
require 'rspec/rails'

require 'combustion'
Combustion.initialize! :action_controller

require_relative '../lib/jd_auth'





RSpec.configure do |config|

  config.expect_with :rspec do |expectations|
    expectations.include_chain_clauses_in_custom_matcher_descriptions = true
  end

  config.mock_with :rspec do |mocks|
    mocks.verify_partial_doubles = true
  end
end
