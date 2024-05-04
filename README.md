<div align="center">

# Smart Blinds

Simple auto blinds framework demo

</div>

## Development

**Option 1: One click start**

For develop frontend or embedded side, could try one click start:

```bash
python run.py
```

**Option 2: Manual start**

To start the server, you will need `Rust` installed on your machine. Then, run
the following command:

```bash
cargo run --package lumisync-server --bin server
```

To work on the web application, you should have `Node.js(LTS version)` and `npm`
installed. Then, run the following command:

```bash
npm install
npm run web
```

## Assembly

The ideal way to assemble the sensor and blinds.

![room.png](docs/room.png)

### Materials

* 2x Arduino * (nano)
* 28BYJ-48 stepper motor
* LM393 Light-Dependent Resistor (LDR)

### Procedural

TODO

## Design

A user group include a group of users and a group of sensors, each user able to
control one or multiple windows, each window above link multiple sensors as data
source.

## Sample

Create sample migration database, create a file `migrate.sql` and copy following
code inside.

```sql
-- Insert sample data into 'groups'
INSERT INTO groups (name) VALUES ('sample');

-- Insert sample data into 'users'
-- Password: test
INSERT INTO users (group_id, email, password, role) VALUES (1, 'test@test.com', '$argon2id$v=19$m=19456,t=2,p=1$zk5JmuovvG7B6vyGGmLxDQ$qoqCpKkqrgoVjeTGa5ewrqFpuPUisTCDnEiPz6Dh/oc', 'admin');

-- Insert sample data into 'settings'
INSERT INTO settings (user_id, light, temperature) VALUES (1, 6, 22.5);

-- Insert sample data into 'windows'
INSERT INTO windows (user_id, name, state) VALUES (1, 'Living Room Left', 0);
INSERT INTO windows (user_id, name, state) VALUES (1, 'Living Room Right', 0);

-- Insert sample data into 'sensors'
INSERT INTO sensors (group_id, name) VALUES (1, 'SENSOR-MOCK');

-- Insert sample data into 'windows_sensors_link'
INSERT INTO windows_sensors_link (window_id, sensor_id) VALUES (1, 1);
INSERT INTO windows_sensors_link (window_id, sensor_id) VALUES (2, 1);
```
Add config into `configs/development.toml`:

```toml
[database]
migrate = "{PATH_TO_FILE}/migrate.sql"
```