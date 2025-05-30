use contender_core::generator::RandSeed;
use contender_core::generator::seeder::SeedValue;
use std::fs;
use std::path::Path;

static SEEDFILE_PATH: &str = ".seed";

pub struct Seedfile {
    seed: RandSeed,
}

impl Seedfile {
    pub fn new() -> Self {
        let seed = if !Path::new(SEEDFILE_PATH).exists() {
            let _ = fs::File::create(SEEDFILE_PATH);
            let seed = RandSeed::new();
            let _ = fs::write(SEEDFILE_PATH, seed.as_bytes());
            seed
        } else {
            let seed_bytes = fs::read(SEEDFILE_PATH).expect("Failed to read seed file");
            RandSeed::seed_from_bytes(&seed_bytes)
        };
        Self { seed }
    }

    pub fn seed(&self) -> &RandSeed {
        &self.seed
    }
}
