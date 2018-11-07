module JdAuth
  class Configuration
    attr_accessor :redis_url, :redis_sentinels, :application_resource_id, :host, :application_resource_encryption_key, :login_path

    def initialize
      @redis_url = nil
      @redis_sentinels = nil
      @application_resource_id = nil
      @host = nil
      @application_resource_encryption_key = nil
      @login_path = nil
    end
  end
end
