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