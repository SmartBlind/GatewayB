use std::error::Error;
use std::fs::OpenOptions;
use std::io::Write;

use lumisync_analyser::criterion::Mse;
use lumisync_analyser::random_forest::RandomForestBuilder;
use lumisync_analyser::table::TableBuilder;

fn main() -> Result<(), Box<dyn Error>> {
    let mut table_builder = TableBuilder::new();
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let dataset_path = format!("{}/datasets/room_blinds.csv", manifest_dir);
    let model_path = format!("{}/models/room_blinds.rf", manifest_dir);
    table_builder.add_csv(dataset_path).unwrap();

    let table = table_builder.build()?;

    let regressor = RandomForestBuilder {
        seed: Some(0),
        parallel: true,
        ..Default::default()
    }
        .fit(Mse, table);

    let mut bytes = Vec::new();
    regressor.serialize(&mut bytes)?;

    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .open(model_path)?;

    file.write(&mut bytes).unwrap();

    Ok(())
}