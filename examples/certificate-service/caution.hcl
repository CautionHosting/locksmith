# Copy to the repository root in a dedicated deployment checkout.
enclave "default" {
  build {
    containerfile = "examples/certificate-service/Containerfile"
    app_sources = ["https://codeberg.org/caution/locksmith"]
  }
  resources {
    cpu = 2
    memory_mb = 1024
  }
  network {
    ingress {
      cidr_ipv4 = "0.0.0.0/0"
      port = 8080
      ip_protocol = "tcp"
    }
  }
  unit "default" {
    command = "/start-certificate-service"
    env = {
      CERTIFICATE_BOOTSTRAP = env::vault("CERTIFICATE_BOOTSTRAP")
    }
  }
}
