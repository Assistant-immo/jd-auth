module JdAuth
  class AuthenticatedUser
    attr_accessor :email, :role

    def initialize(params={})
      self.email = params[:email]
      self.role = params[:role]
    end
  end
end