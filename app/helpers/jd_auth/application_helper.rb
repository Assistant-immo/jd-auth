module JdAuth
  module ApplicationHelper
    def jd_auth_authenticate
      begin
        token = (/Token (?<token>.*)/.match("#{request.headers["Authorization"]}") || {})['token']
        @jd_auth_current_user = OpenStruct.new(JdAuth::Token.validate(token))
        unless @jd_auth_current_user.role
          render json: {
              message: 'Forbidden'
          }, status: 403
          return false
        end
      rescue JdAuth::Errors::NoTokenError, JdAuth::Errors::InvalidTokenError, JdAuth::Errors::ExpiredTokenError
        render json: {
            message: 'Invalid authentication',
            code: "please_request_new_token"
        }, status: 401
        return false
      end

      response.set_header("Authorization-Role", @jd_auth_current_user.role)
      response.set_header("Access-Control-Expose-Headers", "Authorization-Role")
      true
    end

    def jd_auth_current_user
      @jd_auth_current_user
    end

    def jd_auth_only_roles roles
      roles.include?(@jd_auth_current_user.role)
    end
  end
end
