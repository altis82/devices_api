require 'pg'

PG_CONN = PG.connect(
  dbname: 'mydb',
  user: 'postgres',
  password: "password",
  host: "localhost"
)
