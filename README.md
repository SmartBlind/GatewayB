## SetUp

Before develop or publish, an override config file is need `configs/development.toml`
or `configs/production.toml`

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
certificate = """-----BEGIN CERTIFICATE-----
{SECURITY CERTIFICATE}
-----END CERTIFICATE-----
"""
key = """
-----BEGIN EC PRIVATE KEY-----
{SECURITY KEY}
-----END EC PRIVATE KEY-----
"""
```