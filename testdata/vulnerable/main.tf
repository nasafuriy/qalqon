provider "aws" {
  region     = "us-east-1"
  secret_key = "hunter2fix"
}

resource "aws_security_group" "web" {
  name = "web"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket_acl" "assets" {
  bucket = "example-assets"
  acl    = "public-read"
}

resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 20
}

terraform {
  backend "s3" {
    bucket = "example-tfstate"
    key    = "app/terraform.tfstate"
    region = "us-east-1"
  }
}
