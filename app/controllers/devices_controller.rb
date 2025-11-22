class DevicesController < ApplicationController
    #use set_device for show, update, destroy, command and status
    before_action :set_device, only: [:show, :update, :destroy, :command, :status]
    #GET /devices
    def index
        devices = Device.all
        render json: devices
    end
    

    def show
        render json: @devices #use the current device
    end
    def create
        d = Device.new(device_params)
        if d.save
            render json: d, status: :created
        else
            render json: {error: "Create failed"}, status: :unprocessable_entity
        end
    end
    def update
        if @device.update(device_params)
            render json: @device
        else
            render json: {error: "Update failed"}, status: :unprocessable_entity
        end
    end
    def destroy
        @device.destroy
        head :no_content
      
    end
    # POST /devices/:id/command
    def command
        cmd =params[:command].to_s.downcase
        
        if cmd =="start"
            @device.update(status: "running")
            render json: {message: "Device started", device: @device}
        elsif cmd=="stop"
            @device.update(status: "stopped")
            render json: {message: "Device stopped", device: @device}
        else
            render json: {error: "Invalid command"}, status: :bad_request
        end
    end

    #GET /device/:id/status
    def status
        render json: {id: @device.id, status: @device.status}
    end
    private
    def set_device
        @device = Device.find(params[:id])
        render json: {error: "Device not found"}, status: :not_found unless @device
    end
    def device_params
        params.require(:device).permit(:info, :status)
    end
    
end