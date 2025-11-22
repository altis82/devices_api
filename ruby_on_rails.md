# Overview

User (email + password bcrypt) — login using email/password.

Login returns JWT (contain user_id, exp).

Client save token và add to header Authorization: Bearer <TOKEN> for all requests.

ApplicationController get token, decode, set current_user. If token not ok → 401.

DevicesController has CRUD + command (start/stop) + status (current status). 

1 — Create project Rails mới (scratch)

start with
```
rails new devices_api --api -d postgresql
cd devices_api
```
**Error** related to the versions of Ruby 3.1.x and Rails 6.1.x.

```
rails new_devices_api --api -d postgresql
/home/system/.rbenv/versions/3.1.4/lib/ruby/gems/3.1.0/gems/activesupport-6.1.7.8/lib/active_support/logger_thread_safe_level.rb:16:in `<module:LoggerThreadSafeLevel>': uninitialized constant ActiveSupport::LoggerThreadSafeLevel::Logger (NameError)

    Logger::Severity.constants.each do |severity|
    ^^^^^^
        from /home/system/.rbenv/versions/3.1.4/lib/ruby/gems/3.1.0/gems/activesupport-6.1.7.8/lib/active_support/logger_thread_safe_level.rb:9:in `<module:ActiveSupport>'
        from /home/system/.rbenv/versions/3.1.4/lib/ruby/gems/3.1.0/gems/activesupport-6.1.7.8/lib/active_support/logger_thread_safe_level.rb:8:in `<top (required)>'
        from <internal:/home/system/.rbenv/versions/3.1.4/lib/ruby/3.1.0/rubygems/core_ext/kernel_require.rb>:85:in `require'
        
```
**Solution**
install Rails 7
```
gem install rails -v 7.1.3
```
Create project 
```
rails _7.1.3_ new devices_api --api -d postgresql

```


2 — Gemfile add pkgs

 Gemfile, add (if --api then ActionController::API is ready):

** Gemfile**
```
gem 'bcrypt', '~> 3.1.18'
gem 'jwt', '~> 2.6'
```

then:
```
bundle install
```
3 — config DB

Configure: config/database.yml to connect PostgreSQL 
create db
```
default: &default
  adapter: postgresql
  encoding: unicode
  database: mydb
  username: postgres
  password: password
  host: localhost
  port: 5432
```
`
rails db:create
`
4 — Tạo User model (dùng has_secure_password)

Generator:

rails g model User email:string:uniq password_digest:string
rails db:migrate


app/models/user.rb:

class User < ApplicationRecord
  has_secure_password

  validates :email, presence: true, uniqueness: true
end

customize without using activerecord
user.rb
```
class User 
    include ActiveModel::Model 
    include ActiveModel::Attributes
    # attributes
    attribute :id, :integer
    attribute :email, :string
    attribute :password, :string
    
    def self.find_my_email(email)
        sql= "SELECT * FROM users WHERE email= $1 LIMIT 1"
        result = PG_CONN.exect_params(sql, [email])
        return nil if result.ntuples==0

        row =result[0]
        User.new(
            id: row["id"]
            email: row["email"],
            password_hash: row["password_hash"]
        )
    end

end

```
auth_controller.rb
```
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
```
pg_connection.rb
```
require 'pg'

PG_CONN = PG.connect(
  dbname: 'mydb'
  user: 'postgres',
  password: "password",
  host: "localhost"
)

```

has_secure_password dùng bcrypt, bạn sẽ tạo user bằng password/password_confirmation.

5 — Tạo Device model

<!-- Generator:

rails g model Device info:text status:string
rails db:migrate -->


app/models/device.rb:

<!-- class Device < ApplicationRecord
  validates :info, presence: true
  validates :status, inclusion: { in: %w[stopped running unknown], message: "%{value} not allowed" }, allow_nil: true

  after_initialize :set_default_status

  def set_default_status
    self.status ||= 'unknown'
  end
end -->
```
class Device
    include ActiveModel::Model 
    include ActiveModel::Attributes

    attribute :id, :integer
    attribute :info, :string
    attribute :status, :string, default: "unknown"

    #=== CRUD FUNCTIONS ===
    def self.all
        sql = 'SELECT * FROM devices ORDER BY id'
        result= PG_CONN.exec(sql)
        result.map do |row|
            Device.new(
                id: row["id"].to_i,
                info: row["info"],
                status: row["status"]
            )
        end
    end

    def self.find(id)
        sql = "SELECT * FROM devices WHERE id= $1 LIMIT 1"
        result = PG_CONN.exec_params(sql, [id])
        return nil if result.ntuples==0

        row= result[0]
        Device.new(
            id: row["id"].to_i,
            info: row["info"],
            status: row["status"]
        )
    end
    def save
        sql = "INSERT INTO devices (info, status) VALUES ($1, $2) RETURNING id"
        result = PG_CONN.exec_params(sql, [info, status])
        self.id = result[0]["id"].to_i
        true
    end
    def update(attrs)
        self.info   = attrs[:info]   if attrs[:info]
        self.status = attrs[:status] if attrs[:status]
    
        sql = "UPDATE devices SET info=$1, status=$2 WHERE id=$3"
        PG_CONN.exec_params(sql, [info, status, id])
        true
    end
    
    def destroy
        sql = "DELETE FROM devices WHERE id = $1"
        PG_CONN.exec_params(sql, [id])
        true
    end
end
```


6 — ApplicationController: token auth helper

Tạo app/controllers/application_controller.rb (API-only):

class ApplicationController < ActionController::API
  before_action :authenticate_request

  private

  # đọc token từ header Authorization: Bearer <token>
  def authenticate_request
    header = request.headers['Authorization']&.split(' ')&.last
    return render_unauthorized unless header

    begin
      decoded = jwt_decode(header)
      @current_user = User.find(decoded[:user_id])
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
    # dùng credentials nếu có, fallback giá trị secret_key_base
    Rails.application.credentials.jwt_secret_key || Rails.application.secret_key_base
  end
end


Giải thích ngắn:

before_action :authenticate_request chạy cho mọi controller kế thừa. Nếu bạn muốn cho một controller public (ví dụ đăng ký/login), override hoặc skip_before_action.

jwt_encode sinh token với exp.

jwt_decode verify token bằng jwt_secret.

7 — Tạo AuthController (login & register)

Tạo controller auth (để cho phép đăng ký / login không cần token):

rails g controller auth


app/controllers/auth_controller.rb:

class AuthController < ApplicationController
  # bypass authenticate for login/register
  skip_before_action :authenticate_request, only: %i[login register]

  # POST /register
  def register
    user = User.new(register_params)
    if user.save
      token = jwt_encode(user_id: user.id)
      render json: { message: 'User created', token: token, user: { id: user.id, email: user.email } }, status: :created
    else
      render json: { errors: user.errors.full_messages }, status: :unprocessable_entity
    end
  end

  # POST /login
  def login
    user = User.find_by(email: params.dig(:user, :email))
    if user&.authenticate(params.dig(:user, :password))
      token = jwt_encode(user_id: user.id)
      render json: { message: 'Logged in', token: token, user: { id: user.id, email: user.email } }, status: :ok
    else
      render json: { error: 'Invalid email or password' }, status: :unauthorized
    end
  end

  private

  def register_params
    params.require(:user).permit(:email, :password, :password_confirmation)
  end
end

8 — DevicesController (CRUD + command + status)

Generator:

rails g controller devices


app/controllers/devices_controller.rb:

class DevicesController < ApplicationController
  before_action :set_device, only: %i[show update destroy command status]

  # GET /devices
  def index
    devices = Device.all
    render json: devices
  end

  # GET /devices/:id
  def show
    render json: @device
  end

  # POST /devices
  def create
    device = Device.new(device_params)
    if device.save
      render json: device, status: :created
    else
      render json: { errors: device.errors.full_messages }, status: :unprocessable_entity
    end
  end

  # PATCH/PUT /devices/:id
  def update
    if @device.update(device_params)
      render json: @device
    else
      render json: { errors: @device.errors.full_messages }, status: :unprocessable_entity
    end
  end

  # DELETE /devices/:id
  def destroy
    @device.destroy
    head :no_content
  end

  # POST /devices/:id/command
  # body: { "command": "start" } or "stop"
  def command
    cmd = params[:command].to_s.downcase
    case cmd
    when 'start'
      # giả lập: set trạng thái running
      @device.update(status: 'running')
      render json: { message: 'Device started', device: @device }
    when 'stop'
      @device.update(status: 'stopped')
      render json: { message: 'Device stopped', device: @device }
    else
      render json: { error: 'Unknown command' }, status: :bad_request
    end
  end

  # GET /devices/:id/status
  def status
    render json: { id: @device.id, status: @device.status }
  end

  private

  def set_device
    @device = Device.find(params[:id])
  rescue ActiveRecord::RecordNotFound
    render json: { error: 'Device not found' }, status: :not_found
  end

  def device_params
    params.require(:device).permit(:info, :status)
  end
end

9 — Routes

Edit config/routes.rb:

Rails.application.routes.draw do
  post '/register', to: 'auth#register'
  post '/login',    to: 'auth#login'

  resources :devices do
    member do
      post 'command'  # POST /devices/:id/command
      get  'status'   # GET  /devices/:id/status
    end
  end
end

10 — Secrets (khuyến nghị)

Đặt key để ký JWT an toàn. Bạn có thể lưu vào credentials hoặc dùng secret_key_base. Ví dụ set bằng credentials:

EDITOR="nano" rails credentials:edit
# thêm:
jwt_secret_key: your_super_secret_here


Hoặc để nhanh, code đã fallback vào Rails.application.secret_key_base.

11 — Tạo user test (console)

Mở rails console:

User.create!(email: 'test@example.com', password: '123456', password_confirmation: '123456')




12 — start server
rails server -p 3000

13 — Test with curl 



curl -X POST http://localhost:3000/register \
  -H "Content-Type: application/json" \
  -d '{"user":{"email":"test@example.com","password":"123456","password_confirmation":"123456"}}'


Login → get token:

curl -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{"user":{"email":"test@example.com","password":"123456"}}'


Response :

{"message":"Logged in","token":"eyJhbGci...","user":{"id":1,"email":"test@example.com"}}


save token. 

create device:

curl -X POST http://localhost:3000/devices \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxLCJleHAiOjE3NjM4Njc5Njl9.sbtW-PwARvS6Y9pU_n-rG5p2Oy23tKdC2wddXAnTtsU" \
  -d '{"device":{"info":"Device A, location: lab"}}'


List devices:

curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxLCJleHAiOjE3NjM4NjgzNTF9.wTxHb098FBZ7SZuc5-JsK6dqwLnmZfNbsKMip1VJ3RY" http://localhost:3000/devices


send command `start`:

curl -X POST http://localhost:3000/devices/1/command \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxLCJleHAiOjE3NjM4NjgzNTF9.wTxHb098FBZ7SZuc5-JsK6dqwLnmZfNbsKMip1VJ3RY" \
  -d '{"command":"start"}'


get status

curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxLCJleHAiOjE3NjM4NjgzNTF9.wTxHb098FBZ7SZuc5-JsK6dqwLnmZfNbsKMip1VJ3RY" http://localhost:3000/devices/1/status


Response:

{"id":1,"status":"running"}
