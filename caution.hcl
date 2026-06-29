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

    http {
      domain = "keymaker.caution.co"
      port   = 8080
    }
  }

  unit "default" {
    command = "/keymaker-hosted"
  }
}
