class ApplicationController < ActionController::API
    before_action :authenticate_request
    
    private
    def authenticate_request
        header = request.headers['Authorization']&.split(' ')&.last
        return render_unauthorized unless header
        begin
            decoded = jwt_decode(header)
            @current_user = User.find_by_id(decoded[:user_id])
            #@current_user = User.find(decoded[:user_id])
        rescue ActiveRecord::RecordNotFound, JWT::DecodeError => e
            render_unauthorized
        end
    end
    def render_unauthorized
        render json: { error: 'Unauthorized' }, status: :unauthorized
    end

    # JWT helpers
    def jwt_encode(payload, exp = 24.hours.from_now.to_i)
        payload[:exp] = exp
        JWT.encode(payload, jwt_secret, 'HS256')
    end
    def jwt_decode(token)
        decoded_array = JWT.decode(token, jwt_secret, true, { algorithm: 'HS256' })
        # decoded_array = [{ "user_id" => 1, "exp" => ... }, { ...header... }]
        HashWithIndifferentAccess.new(decoded_array[0])
      end
    
    def jwt_secret
        Rails.application.credentials.jwt_secret_key || Rails.application.secret_key_base
    end

end
