enclave "default" {
  restart {
    policy        = "always"
    delay_seconds = 0
  }

  build {
    app_sources = [
      "https://codeberg.org/caution/locksmith"
    ]
  }

  network {
    ingress {
      cidr_ipv4 = "0.0.0.0/0"
      port = 8080
      ip_protocol = "tcp"
    }

    # Requried for TLS
    egress {
      cidr_ipv4 = "0.0.0.0/0"
    }

    http {
      domain = "keymaker.caution.co"
      port = 8080
      e2e_encryption {
        mode = "tls"
      }
    }
  }

  unit "default" {
    command = "/keymaker"
  }
}
