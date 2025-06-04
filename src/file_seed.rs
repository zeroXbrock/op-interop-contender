use contender_core::alloy::primitives::U256;
use contender_core::generator::RandSeed;
use contender_core::generator::seeder::{SeedValue, Seeder};
use std::fs;
use std::path::Path;

static SEEDFILE_PATH: &str = ".contender/seed";

#[derive(Clone, Debug)]
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
}

impl Seeder for Seedfile {
    fn seed_values(
        &self,
        amount: usize,
        min: Option<U256>,
        max: Option<U256>,
    ) -> Box<impl Iterator<Item = impl SeedValue>> {
        // this could be modified to return specific sequences to be used by the fuzzer
        self.seed.seed_values(amount, min, max)
    }

    fn seed_from_bytes(seed: &[u8]) -> Self {
        let seed = RandSeed::seed_from_bytes(seed);
        Self { seed }
    }

    fn seed_from_str(seed: &str) -> Self {
        let seed = RandSeed::seed_from_str(seed);
        Self { seed }
    }

    fn seed_from_u256(seed: U256) -> Self {
        let seed = RandSeed::seed_from_u256(seed);
        Self { seed }
    }
}

impl SeedValue for Seedfile {
    fn as_bytes(&self) -> &[u8] {
        self.seed.as_bytes()
    }

    fn as_u256(&self) -> U256 {
        self.seed.as_u256()
    }

    fn as_u128(&self) -> u128 {
        self.seed.as_u128()
    }

    fn as_u64(&self) -> u64 {
        self.seed.as_u64()
    }
}
