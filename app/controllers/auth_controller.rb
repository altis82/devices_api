class AuthController < ApplicationController
    def login
        user = User.find_my_email(params[:email])
        if user && BCrypt::Password.new(user.password_hash) == params[:password]
            token = JWT.encode({ user_id: user.id }, Rails.application.secret_key_base)
            render json: { token: token }
        else
            render json: { error: "Invalid login" }, status: :unauthorized
        end
    end
end