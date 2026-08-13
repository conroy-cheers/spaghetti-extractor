{
  small = {
    resource = {
      cores = 1;
      memory_mib = 768;
      disk_mib = 1024;
    };
    timing = {
      expected_seconds = 30;
      timeout_seconds = 300;
    };
  };
  medium = {
    resource = {
      cores = 2;
      memory_mib = 1536;
      disk_mib = 4096;
    };
    timing = {
      expected_seconds = 180;
      timeout_seconds = 1800;
    };
  };
  large = {
    resource = {
      cores = 4;
      memory_mib = 3584;
      disk_mib = 16384;
    };
    timing = {
      expected_seconds = 900;
      timeout_seconds = 7200;
    };
  };
  oracle = {
    resource = {
      cores = 8;
      memory_mib = 32768;
      disk_mib = 32768;
    };
    timing = {
      expected_seconds = 3600;
      timeout_seconds = 21600;
    };
  };
}
