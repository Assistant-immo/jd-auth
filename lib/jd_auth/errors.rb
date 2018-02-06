module JdAuth
  module Errors
    class RedisNotConfiguredError < StandardError; end
    class NoTokenError < StandardError; end
    class InvalidTokenError < StandardError; end
    class ExpiredTokenError < StandardError; end
    class InvalidIpForTokenError < StandardError; end
  end
end