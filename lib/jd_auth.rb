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
    unless @redis
      if self.configuration.redis_sentinels.present?
        host, port = self.configuration.redis_sentinels.split(':')
        sentinel = /(?<host>.*)\:(?<port>[0-9]+)/.match(self.configuration.redis_sentinels).named_captures.symbolize_keys
        @redis = Redis.new(url: self.configuration.redis_url, sentinels: [{
          host: host,
          port: port.to_i
          }], role: :slave)
      else
        @redis = Redis.new(url: self.configuration.redis_url)
      end
    end

    @redis
  end

  def self.login_url(redirect_url, force_login=false)
    if JdAuth.configuration.login_path && !force_login
      add_params_to_url(JdAuth.configuration.login_path, url:redirect_url)
    else
      add_params_to_url("#{JdAuth.configuration.host}/public_api/v1/authentication_tokens/new", application_resource_id: JdAuth.configuration.application_resource_id, url:redirect_url)
    end
  end

  class Railtie < Rails::Railtie
    initializer "jd_auth.action_controller" do
      ActiveSupport.on_load(:action_controller) do
        include JdAuth::ControllersHelper
      end
    end
  end

  def self.add_params_to_url(url, params)
    uri = URI.parse(url)
    uri.query = params.merge(Rack::Utils.parse_query(uri.query)).to_query
    uri.to_s
  end

end
