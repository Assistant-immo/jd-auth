module JdAuth
  class Configuration
    attr_accessor :redis_url, :application_resource_id

    def initialize
      @redis_url = nil
      @application_resource_id = nil
    end
  end
end
