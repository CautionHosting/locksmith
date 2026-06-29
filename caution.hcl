enclave "main" {
  build {
    app_sources = [
      "https://codeberg.org/caution/locksmith"
    ]
  }

  network {
    ingress {
      cidr_ipv4   = "0.0.0.0/0"
      port        = 8080
      ip_protocol = "tcp"
    }
  }

  unit "default" {
    command = "/keymaker"
  }
}
