class User 
    include ActiveModel::Model 
    include ActiveModel::Attributes
    # attributes
    attribute :id, :integer
    attribute :email, :string
    attribute :password_hash, :string
    
    def self.find_my_email(email)
        sql= "SELECT * FROM users WHERE email= $1 LIMIT 1"
        result = PG_CONN.exec_params(sql, [email])
        return nil if result.ntuples==0

        row =result[0]
        User.new(
            id: row["id"],
            email: row["email"],
            password_hash: row["password_hash"]
        )
    end

end
