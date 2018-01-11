module JdAuth

  class Token

    def self.validate token
      raise JdAuth::Errors::NoTokenError if token == nil || token == ''

      encrypted_json_token_info = JdAuth.redis.get(token)

      raise JdAuth::Errors::InvalidTokenError unless encrypted_json_token_info

      begin
        decrypter = OpenSSL::Cipher::Cipher.new('aes-256-cbc').decrypt
        decrypter.key = Digest::SHA256.digest(ENV['JD_AUTH_ENCRYPTION_KEY'])
        json_token_info = decrypter.update(Base64.decode64(encrypted_json_token_info.to_s)) + decrypter.final
      rescue
        JdAuth::Errors::InvalidTokenError
      end

      begin
        token_info = JSON.parse("#{json_token_info}")
      rescue JSON::ParserError
        raise JdAuth::Errors::InvalidTokenError
      end

      %w"user_email application_resource_id".each do |param_key|
        raise JdAuth::Errors::InvalidTokenError unless token_info[param_key]
      end

      begin
        validity_start = DateTime.parse(token_info['validity_start'])
        validity_end = DateTime.parse(token_info['validity_end'])
      rescue ArgumentError
        raise JdAuth::Errors::InvalidTokenError
      end


      raise JdAuth::Errors::InvalidTokenError unless token_info['application_resource_id'] == JdAuth.configuration.application_resource_id.to_i

      now = DateTime.now

      raise JdAuth::Errors::ExpiredTokenError unless validity_start <= now
      raise JdAuth::Errors::ExpiredTokenError unless validity_end > now

      {
          user_email: token_info['user_email'],
          role: token_info['role']
      }
    end
  end
end