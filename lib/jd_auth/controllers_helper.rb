module JdAuth
  module ControllersHelper

    KEY_TOKEN = 'jd_auth_token'
    KEY_FETCHING_TOKEN = 'jd_auth_fetching_token'

    PARAM_TOKEN = 'token'

    RESPONSE_UNAUTHORIZED = 'failed'
    RESPONSE_FETCH_TOKEN = 'redirect'
    RESPONSE_SUCCESS = 'success'
    RESPONSE_REMOVE_TOKEN = 'remove_token'


    def jd_auth_authenticate
      begin
        token = (/Token (?<token>.*)/.match("#{request.headers["Authorization"]}") || {})['token']
        @jd_auth_current_user = JdAuth::Token.validate(token, request.remote_ip)
        unless @jd_auth_current_user.role
          render json: {
              message: 'Forbidden'
          }, status: 403
          return false
        end
      rescue JdAuth::Errors::NoTokenError, JdAuth::Errors::InvalidTokenError, JdAuth::Errors::ExpiredTokenError, JdAuth::Errors::InvalidIpForTokenError
        render json: {
            message: 'Invalid authentication',
            code: "please_request_new_token"
        }, status: 401
        return false
      end

      if Rails::VERSION::MAJOR >= 5
        response.set_header("Authorization-Role", @jd_auth_current_user.role)
        response.set_header("Authorization-Identifier", @jd_auth_current_user.email)
        response.set_header("Access-Control-Expose-Headers", "Authorization-Role, Authorization-Identifier")
      else
        response.headers["Authorization-Role"] = @jd_auth_current_user.role
        response.headers["Authorization-Identifier"] = @jd_auth_current_user.email
        response.headers["Access-Control-Expose-Headers"] = "Authorization-Role, Authorization-Identifier"
      end
      true
    end

    def jd_auth_current_user
      @jd_auth_current_user
    end

    def jd_auth_only_roles(roles)
      roles.include?(@jd_auth_current_user.role)
    end

    def jd_auth_authenticate_sinatra_server(sinatra_server, only_roles=nil)

      sinatra_server.before(/.*/) do
        params = request.params
        session = request.env['rack.session']

        if params[PARAM_TOKEN]
          session.merge!({KEY_TOKEN => params[PARAM_TOKEN]})
          redirect remove_token_param_from_url(request.url)
        else
          resp = jd_auth_backend_authenticate session, request.ip, only_roles

          if resp == RESPONSE_FETCH_TOKEN
            redirect JdAuth.login_url(request.url)
          elsif resp == RESPONSE_UNAUTHORIZED
            halt 401, "Not authorized\n"
          end
        end
      end
    end

    def jd_auth_authenticate_server
      if params[PARAM_TOKEN]
        session.merge!({KEY_TOKEN => params[PARAM_TOKEN]})
        redirect_to remove_token_param_from_url(request.url)
        return false
      else
        resp = jd_auth_backend_authenticate session, request.ip, nil

        if resp == RESPONSE_FETCH_TOKEN
          redirect_to JdAuth.login_url(request.url)
          return false
        elsif resp == RESPONSE_UNAUTHORIZED
          render "Not authorized\n", status: 401
          return false
        end
      end
      true
    end

    def jd_auth_go_to_login(redirect_url=nil)
      login_url = JdAuth.login_url(redirect_url.present? ? redirect_url : request.url, true)
      #google_account_chooser_url = "https://accounts.google.com/AccountChooser?continue=https://appengine.google.com/_ah/logout?continue=#{login_url}"

      redirect_to google_account_chooser_url
    end

    def jd_auth_backend_authenticate(session, origin_ip, only_roles=nil)
      token = session.fetch(KEY_TOKEN, nil)

      if token.blank?
        session.merge!({KEY_FETCHING_TOKEN => true})
        return RESPONSE_FETCH_TOKEN
      end

      token_is_valid = false
      begin
        @jd_auth_current_user = JdAuth::Token.validate(token, origin_ip)

        if @jd_auth_current_user.role.blank? || (only_roles && !only_roles.include?(@jd_auth_current_user.role))
          return RESPONSE_UNAUTHORIZED
        end

        token_is_valid = true
      rescue JdAuth::Errors::NoTokenError, JdAuth::Errors::InvalidTokenError, JdAuth::Errors::ExpiredTokenError
        token_is_valid = false
      end

      if token_is_valid
        session.delete(KEY_FETCHING_TOKEN)
        return RESPONSE_SUCCESS
      else
        if session.fetch(KEY_FETCHING_TOKEN, false)
          session.delete(KEY_FETCHING_TOKEN)
          return RESPONSE_UNAUTHORIZED
        else
          session.merge!({KEY_FETCHING_TOKEN => true})
          return RESPONSE_FETCH_TOKEN
        end
      end
    end

    private

    def remove_token_param_from_url url
      uri = URI.parse(url)
      uri.query = Rack::Utils.parse_query(uri.query).except("token").except("application_resource_id").to_query
      uri.to_s
    end

  end
end
