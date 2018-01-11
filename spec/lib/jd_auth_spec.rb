require_relative '../spec_helper'

describe JdAuth do

  before :each do
    JdAuth.configuration = nil
  end

  describe :configure do

    it "populates configuration instance variable" do
      JdAuth.configure do |configuration|
        configuration.application_resource_id = 13
        configuration.redis_url = "AnUrl"
      end

      expect(JdAuth.configuration.application_resource_id).to eq(13)
      expect(JdAuth.configuration.redis_url).to eq("AnUrl")
    end

  end

  describe :redis do
    it "should raise if redis_url is not configured" do
      expect{JdAuth.redis}.to raise_error(JdAuth::Errors::RedisNotConfiguredError)
    end

    it "should create a redis instance if redis_url is not configured" do
      JdAuth.configure do |configuration|
        configuration.redis_url = "redis://1.1.1.1:6379/0"
      end
      expect(Redis).to receive(:new).with({
          url: "redis://1.1.1.1:6379/0"
                                          }).and_return("redis_instance")
      expect(JdAuth.redis).to eq("redis_instance")
    end
  end

end