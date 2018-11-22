module RedmineOpenidConnect
  module ApplicationControllerPatch
    def self.included(base)
      base.send(:include, InstanceMethods)

      base.class_eval do
        alias_method_chain :require_login, :openid_connect
        alias_method_chain :logged_user=, :openid_connect
      end
    end
  end # ApplicationControllerPatch

  module InstanceMethods
    def token_valid?
      if session[:oic_session_id].blank?
        oic_session = OicSession.create
        session[:oic_session_id] = oic_session.id
        return false
      else
        begin
          oic_session = OicSession.find session[:oic_session_id]
        rescue ActiveRecord::RecordNotFound => e
          oic_session = OicSession.create
          session[:oic_session_id] = oic_session.id
          return false
        end
        return false if oic_session.expired?
        response = oic_session.refresh_access_token!
        if response["error"].present?
          oic_session.destroy
          return false
        end
      end

      true
    end

    def require_login_with_openid_connect
      return require_login_without_openid_connect unless OicSession.enabled?

      if !User.current.logged? #!token_valid?
        redirect_to oic_login_url
        return false
      end
      true
    end

    # set the current user _without_ resetting the session first
    def logged_user_with_openid_connect=(user)
      return send(:logged_user_without_openid_connect=, user) unless OicSession.enabled?

      if user && user.is_a?(User)
        User.current = user
        start_user_session(user)
      else
        User.current = User.anonymous
      end
    end
  end # InstanceMethods
end
