## SetUp

Before development or publishing, an override config file is needed:
`configs/development.toml` for development settings or
`configs/production.toml` for production settings.

```toml
[gateway]
address = "....amazonaws.com"
port = 8883
client_id = "{MYID}"

[gateway.topic]
prefix_env = "{GROUPID PREFIX ENVIRONMENT}"
prefix_country = "{GROUPID PREFIX COUNTRY}"
customer_id = "{GROUPID CUSTOMER ID}"

[gateway.auth]
cert_path = "/etc/ssl/certs/{CLIENT CERTIFICATE}.pem"
key_path = "/etc/ssl/private/{CLIENT KEY}.key"
```

## Development

To start the server, you will need Rust installed on your machine. Then, run the
following command:

```bash
cargo run --package lumisync-server --bin server
```

To work on the web application, you should have Node.js and npm installed. Then,
run the following command:

```bash
npm install
npm run web
```

## Sample migration

```sql
-- Insert sample data into 'users'
INSERT INTO users (email) VALUES ('test@test.com');

-- Insert sample data into 'settings'
INSERT INTO settings (user_id, light, temperature) VALUES (1, 6, 22.5);

-- Insert sample data into 'windows'
INSERT INTO windows (user_id, sensor_id, name, state) VALUES (1, 'SENSOR01', 'Living Room', 0);
INSERT INTO windows (user_id, sensor_id, name, state) VALUES (1, 'SENSOR02', 'Balcony', 0);
```