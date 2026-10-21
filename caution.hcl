enclave "default" {
  restart {
    policy        = "always"
    delay_seconds = 0
  }

  build {
    app_sources = [
      "https://git.caution.co/public/locksmith"
    ]
  }

  network {
    http {
      port   = 8080
      domain = "keymaker.caution.co"
    }

    ingress {
      cidr_ipv4 = "0.0.0.0/0"
      port = 8080
      ip_protocol = "tcp"
    }
  }

  unit "default" {
    command = "/keymaker"
  }
}
