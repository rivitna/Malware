use std::env;
use std::time::{Duration, Instant};
use std::fs::File;
use std::io::Write;


fn main() {

  let args: Vec<String> = env::args().collect();

  let size: usize = args[1].parse().unwrap();

  let mut _rnd_data: Vec<u8> = vec![0; size];

  rand_data(_rnd_data.as_mut_slice());

  let mut file = File::create("rand_data.bin").unwrap();
  file.write(&_rnd_data);
}


fn rand_data(data: &mut [u8]) {

  let _start = Instant::now();

  for byte in data {
    *byte = rand32(_start) as u8;
  }
}


fn rand32(start: Instant) -> u32 {

  let _now = Instant::now();

  let _s = _now.duration_since(start);

  _s.subsec_nanos()
}
