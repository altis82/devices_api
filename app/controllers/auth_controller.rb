class AuthController < ApplicationController
    skip_before_action :authenticate_request, only: [:login]
  
    def login
      email = params[:user][:email]
      password = params[:user][:password]
  
      user = User.find_my_email(email)
      return render json: { error: "Invalid login" }, status: :unauthorized unless user
  
      # Password stored in DB is bcrypt hash
      if BCrypt::Password.new(user.password_hash) == password
        token = jwt_encode({ user_id: user.id })
        render json: { token: token }
      else
        render json: { error: "Invalid login" }, status: :unauthorized
      end
    end
  end
  