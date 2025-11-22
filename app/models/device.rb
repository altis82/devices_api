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