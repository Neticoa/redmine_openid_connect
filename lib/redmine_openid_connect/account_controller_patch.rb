module RedmineOpenidConnect
  module AccountControllerPatch

    def successful_authentication user
      if OicSession.disabled? || params[:local_login].present? || request.post?
        return super user
      end
      # TODO
      if session[:remember_url]
        params[:back_url] = session[:remember_url]
        session[:remember_url] = nil
      end
      return super
    end

    def login
      if OicSession.disabled? || params[:local_login].present? || request.post?
        return super
      end
      
      redirect_to oic_login_url
    end

    def logout
      if OicSession.disabled? || params[:local_login].present?
        return super
      end

      oic_session = OicSession.find(session[:oic_session_id])
      oic_session.destroy
      logout_user
      reset_session
      redirect_to oic_session.end_session_url
    rescue ActiveRecord::RecordNotFound => e
      redirect_to oic_local_logout_url
    end

    # performs redirect to SSO server
    def oic_login
      if session[:oic_session_id].blank?
        oic_session = OicSession.create
        session[:oic_session_id] = oic_session.id
      else
        begin
          oic_session = OicSession.find session[:oic_session_id]
        rescue ActiveRecord::RecordNotFound => e
          oic_session = OicSession.create
          session[:oic_session_id] = oic_session.id
        end

        if oic_session.complete? && oic_session.expired?
          response = oic_session.refresh_access_token!
          if response[:error].present?
            oic_session.destroy
            oic_session = OicSession.create
            session[:oic_session_id] = oic_session.id
          end
        end
      end
      
      redirect_to oic_session.authorization_url
    end

    def oic_local_logout
      logout_user
      reset_session
    end

    def oic_local_login
      if params[:code]
        oic_session = OicSession.find(session[:oic_session_id])

        unless oic_session.present?
          return invalid_credentials
        end

        # verify request state or reauthorize
        unless oic_session.state == params[:state]
          flash[:error] = "Invalid OpenID Connect request."
          return redirect_to oic_local_logout
        end

        oic_session.update_attributes!(authorize_params)

        # verify id token nonce or reauthorize
        if oic_session.id_token.present?
          unless oic_session.claims['nonce'] == oic_session.nonce
            flash[:error] = "Invalid ID Token."
            return redirect_to oic_local_logout
          end
        end
        
        # get access token and user info
        oic_session.get_access_token!
        user_info = oic_session.get_user_info!

        attributes = {
          firstname: user_info["given_name"],
          lastname: user_info["family_name"],
          mail: user_info["email"],
          last_login_on: Time.now
        }

        # Check if there's already an existing user
        user = User.find_by_mail(user_info["email"])

        if user.nil?
          unless oic_session.authorized?
            return invalid_credentials
          end
          user = User.new

          user.login = user_info["preferred_username"]
          user.assign_attributes attributes

          if user.save
            user.update_attribute(:admin, true) if oic_session.admin?
            oic_session.user_id = user.id
            oic_session.save!
            if oic_session.authorized? 
              user.activate!
            else
              user.lock!
            end
            # Existing record
            if user.active?
              successful_authentication(user)
            else
              handle_inactive_user(user)
            end
          else
            flash.now[:warning] ||= "Unable to create user #{user.login}: "
            user.errors.full_messages.each do |error|
              logger.warn "Unable to create user #{user.login} due to #{error}"
              flash.now[:warning] += "#{error}. "
            end
            return invalid_credentials
          end
        else
          user.update_attribute(:admin, oic_session.admin?)
          user.assign_attributes(attributes)
          if oic_session.authorized? 
            user.activate!
          else
            user.lock!
          end
          oic_session.user_id = user.id
          oic_session.save!
          # Existing record
          if user.active?
            successful_authentication(user)
          else
            handle_inactive_user(user)
          end
        end # if user.nil?
      end
    end

    def invalid_credentials
      return super unless OicSession.enabled?

      logger.warn "Failed login for '#{params[:username]}' from #{request.remote_ip} at #{Time.now.utc}"
      flash.now[:error] = (l(:notice_account_invalid_credentials) + ". " + "<a href='#{signout_path}'>Try a different account</a>").html_safe
    end

    def rpiframe
      @oic_session = OicSession.find(session[:oic_session_id])
      render layout: false
    end

    def authorize_params
      # compatible with both rails 3 and 4
      if params.respond_to?(:permit)
        params.permit(
          :code,
          :id_token,
          :session_state,
        )
      else
        params.select do |k,v|
          [
            'code',
            'id_token',
            'session_state',
          ].include?(k)
        end
      end
    end
  end # InstanceMethods
end
