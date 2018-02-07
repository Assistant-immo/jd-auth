require_relative '../../spec_helper'

describe JdAuth::Token do

  describe :validate do


    let(:encryption_key) { SecureRandom.hex(64) }

    before do

      def encrypt token_info
        encrypter = OpenSSL::Cipher.new('aes-256-cbc').encrypt
        encrypter.key = Digest::SHA256.digest(encryption_key)
        Base64.encode64(encrypter.update(token_info.to_s) + encrypter.final)
      end
    end

    context "Token is nil" do
      it "should raise" do
        expect{JdAuth::Token.validate nil, "10.0.0.22"}.to raise_error(JdAuth::Errors::NoTokenError)
      end
    end

    context "Token is empty string" do
      it "should raise" do
        expect{JdAuth::Token.validate '', "10.0.0.22"}.to raise_error(JdAuth::Errors::NoTokenError)
      end
    end

    context "Token is a non-empty string" do
      before do
        @token = "abcde"
      end

      context "getting redis fails" do
        it "should raise" do
          expect(JdAuth).to receive(:redis).and_raise(JdAuth::Errors::RedisNotConfiguredError)

          expect{JdAuth::Token.validate @token, "10.0.0.22"}.to raise_error(JdAuth::Errors::RedisNotConfiguredError)
        end
      end

      context "getting redis succeeds" do
        before do
          redis = double("redis")
          allow(redis).to receive(:get).with("unexisting_key").and_return nil
          allow(redis).to receive(:get).with("invalid_json_key").and_return "xx"
          allow(redis).to receive(:get).with("valid_empty_json_key").and_return encrypt("{}")
          allow(redis).to receive(:get).with("invalid_origin_ip").and_return(encrypt({
                                                                                              application_resource_id: 13,
                                                                                              user_email: 'john@doe.com',
                                                                                              validity_start: "abcd",
                                                                                              validity_end: "2010-01-02T00:00:00",
                                                                                              role: "admin",
                                                                                              origin_ip: "10.0.1.12"
                                                                                          }.to_json))

          allow(redis).to receive(:get).with("invalid_dates_json_key").and_return(encrypt({
                                                                                      application_resource_id: 13,
                                                                                      user_email: 'john@doe.com',
                                                                                      validity_start: "abcd",
                                                                                      validity_end: "2010-01-02T00:00:00",
                                                                                      role: "admin",
                                                                                      origin_ip: "10.0.0.22"
                                                                                  }.to_json))
          allow(redis).to receive(:get).with("valid_correct_json_key").and_return(encrypt({
            application_resource_id: 13,
            user_email: 'john@doe.com',
            validity_start: "2010-01-01T00:00:00",
            validity_end: "2010-01-03T00:00:00",
            role: "admin",
            origin_ip: "10.0.0.22"
          }.to_json))
          expect(JdAuth).to receive(:redis).and_return(redis)
        end

        context "key does not exist" do
          it "should raise" do
            expect{JdAuth::Token.validate "unexisting_key", "10.0.0.22"}.to raise_error(JdAuth::Errors::InvalidTokenError)
          end
        end


        context "invalid json key" do
          it "should raise" do
            expect{JdAuth::Token.validate "invalid_json_key", "10.0.0.22"}.to raise_error(JdAuth::Errors::InvalidTokenError)
          end
        end

        context "empty json key" do
          it "should raise" do
            expect{JdAuth::Token.validate "valid_empty_json_key", "10.0.0.22"}.to raise_error(JdAuth::Errors::InvalidTokenError)
          end
        end


        context "valid json key, origin_ip does not match" do
          # Commented for now as network is not fully set to pass IP yet
          xit "should raise" do
            JdAuth.configure do |configuration|
              configuration.application_resource_id = 12
              configuration.application_resource_encryption_key = encryption_key
            end
            expect{JdAuth::Token.validate "invalid_origin_ip", "10.0.0.22"}.to raise_error(JdAuth::Errors::InvalidIpForTokenError)
          end
        end

        context "invalid dates json key, application_resource_id does not match" do
          it "should raise" do
            JdAuth.configure do |configuration|
              configuration.application_resource_id = 12
              configuration.application_resource_encryption_key = encryption_key
            end
            expect{JdAuth::Token.validate "invalid_dates_json_key", "10.0.0.22"}.to raise_error(JdAuth::Errors::InvalidTokenError)
          end
        end

        context "valid json key, application_resource_id does not match" do
          it "should raise" do
            JdAuth.configure do |configuration|
              configuration.application_resource_id = 12
              configuration.application_resource_encryption_key = encryption_key
            end
            expect{JdAuth::Token.validate "valid_correct_json_key", "10.0.0.22"}.to raise_error(JdAuth::Errors::InvalidTokenError)
          end
        end

        context "valid json key, before validity" do
          it "should raise" do
            JdAuth.configure do |configuration|
              configuration.application_resource_id = 13
              configuration.application_resource_encryption_key = encryption_key
            end
            allow(DateTime).to receive(:now).and_return(DateTime.parse("2009-12-01T00:00:00"))
            expect{JdAuth::Token.validate "valid_correct_json_key", "10.0.0.22"}.to raise_error(JdAuth::Errors::ExpiredTokenError)
          end
        end

        context "valid json key, after validity" do
          it "should raise" do
            JdAuth.configure do |configuration|
              configuration.application_resource_id = 13
              configuration.application_resource_encryption_key = encryption_key
            end
            allow(DateTime).to receive(:now).and_return(DateTime.parse("2010-02-02T00:00:00"))
            expect{JdAuth::Token.validate "valid_correct_json_key", "10.0.0.22"}.to raise_error(JdAuth::Errors::ExpiredTokenError)
          end
        end

        context "valid json key, valid" do
          it "should return token info" do
            JdAuth.configure do |configuration|
              configuration.application_resource_id = 13
              configuration.application_resource_encryption_key = encryption_key
            end
            allow(DateTime).to receive(:now).and_return(DateTime.parse("2010-01-02T00:00:00"))
            authenticated_user = JdAuth::Token.validate("valid_correct_json_key", "10.0.0.22")

            expect(authenticated_user.email).to eq("john@doe.com")
            expect(authenticated_user.role).to eq("admin")
          end
        end

      end
    end

  end
end