require 'jd_auth/configuration'
require 'jd_auth/errors'
require 'jd_auth/token'
require 'jd_auth/controllers_helper'
require 'jd_auth/authenticated_user'


require 'redis'

module JdAuth

  class << self
    attr_accessor :configuration
  end

  def self.configuration
    @configuration ||= Configuration.new
  end

  def self.configure
    yield(configuration)
  end

  def self.redis
    raise JdAuth::Errors::RedisNotConfiguredError unless self.configuration.redis_url.present?
    @redis ||= Redis.new(url: self.configuration.redis_url)
  end

  class Railtie < Rails::Railtie
    initializer "jd_auth.action_controller" do
      ActiveSupport.on_load(:action_controller) do
        include JdAuth::ControllersHelper
      end
    end
  end

end
