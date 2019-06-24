module RedmineOpenidConnect
  module ApplicationControllerPatch

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

    def require_login
      return super unless OicSession.enabled?

      if !User.current.logged? #!token_valid?
        if request.get?
          url = request.original_url
        else
          url = url_for(:controller => params[:controller], :action => params[:action], :id => params[:id], :project_id => params[:project_id])
        end
        session[:remember_url] = url
        redirect_to oic_login_url
        return false
      end
      true
    end

    # set the current user _without_ resetting the session first
    def logged_user=(user)
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
