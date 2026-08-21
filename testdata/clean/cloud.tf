resource "aws_db_instance" "app" {
  engine              = "postgres"
  publicly_accessible = false
  storage_encrypted   = true
}

resource "google_compute_firewall" "ssh" {
  name          = "allow-ssh"
  network       = "default"
  source_ranges = ["10.0.0.0/8"]

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
  source_address_prefix  = "10.0.0.0/8"
}

resource "azurerm_storage_account" "assets" {
  name                      = "assetsfixture"
  min_tls_version           = "TLS1_2"
  enable_https_traffic_only = true
}

resource "aws_iam_policy" "deploy" {
  name = "deploy"

  policy = <<-EOT
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": ["s3:GetObject", "s3:PutObject"],
        "Resource": "arn:aws:s3:::artifacts/*"
      }
    ]
  }
  EOT
}

module "vpc" {
  source = "git::https://git.example.com/infra/vpc.git//modules/vpc?ref=v1.4.0"
}
