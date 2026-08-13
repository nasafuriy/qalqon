provider "aws" {
  region = "us-east-1"
}

resource "aws_security_group" "web" {
  name = "web"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}

resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 20
  encrypted         = true
}

terraform {
  backend "s3" {
    bucket  = "example-tfstate"
    key     = "app/terraform.tfstate"
    region  = "us-east-1"
    encrypt = true
  }
}
