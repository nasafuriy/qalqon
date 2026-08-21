resource "aws_db_instance" "app" {
  engine              = "postgres"
  publicly_accessible = true
  storage_encrypted   = true
}

resource "google_compute_firewall" "ssh" {
  name          = "allow-ssh"
  network       = "default"
  source_ranges = ["0.0.0.0/0"]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

resource "azurerm_network_security_rule" "rdp" {
  name                   = "allow-rdp"
  direction              = "Inbound"
  access                 = "Allow"
  protocol               = "Tcp"
  destination_port_range = "3389"
  source_address_prefix  = "*"
}

resource "azurerm_storage_account" "assets" {
  name                      = "assetsfixture"
  min_tls_version           = "TLS1_0"
  enable_https_traffic_only = false
}

resource "aws_iam_policy" "deploy" {
  name = "deploy"

  policy = <<-EOT
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": "*",
        "Resource": "*"
      }
    ]
  }
  EOT
}

module "vpc" {
  source = "git::https://git.example.com/infra/vpc.git//modules/vpc"
}
