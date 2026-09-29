enclave "default" {
  restart {
    policy        = "always"
    delay_seconds = 0
  }

  build {
    containerfile = "examples/certificate-service/Containerfile"
    app_sources = ["https://codeberg.org/caution/locksmith"]
  }
  resources {
    cpu = 2
    memory_mb = 1024
  }
  network {
    http {
      domain = "key-service.kobl.one"
      port = 8080
    }
    ingress {
      cidr_ipv4 = "0.0.0.0/0"
      port = 8080
      ip_protocol = "tcp"
    }
  }
  unit "default" {
    command = "/start-certificate-service"
    env = {
      PUBLIC_CERTIFICATE_SERVICE_TOKEN = env::vault("PUBLIC_CERTIFICATE_SERVICE_TOKEN")
    }
  }
}
