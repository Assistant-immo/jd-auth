module JdAuth
  class Configuration
    attr_accessor :redis_url, :application_resource_id, :host, :application_resource_encryption_key

    def initialize
      @redis_url = nil
      @application_resource_id = nil
      @host = nil
      @application_resource_encryption_key = nil
    end
  end
end
