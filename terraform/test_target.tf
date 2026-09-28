# Demo "compromised" instance (deploy_test_target = true).
# Amazon Linux 2023 in a subnet with NO internet route. First boot plants inert
# indicators (EICAR test file, fake miner config, cron persistence, rogue SSH
# key, webshell on a second data volume) for the pipeline to find.

data "aws_ssm_parameter" "al2023" {
  count = var.deploy_test_target ? 1 : 0
  name  = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

resource "aws_security_group" "test_target" {
  count       = var.deploy_test_target ? 1 : 0
  name        = "${local.name}-demo-target"
  description = "Demo target - no inbound, no outbound"
  vpc_id      = aws_vpc.forensics.id
  tags        = { Name = "${local.name}-demo-target" }
}

resource "aws_instance" "test_target" {
  count                  = var.deploy_test_target ? 1 : 0
  ami                    = data.aws_ssm_parameter.al2023[0].value
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.workload[0].id
  vpc_security_group_ids = [aws_security_group.test_target[0].id]
  user_data              = file("${path.module}/../src/test-target/user-data.sh")
  monitoring             = true
  ebs_optimized          = true

  metadata_options {
    http_tokens   = "required"
    http_endpoint = "enabled"
  }

  # Encrypted with the account default aws/ebs key, like most real workloads.
  root_block_device {
    volume_type = "gp3"
    volume_size = 8
    encrypted   = true
  }

  tags = {
    Name        = "${local.name}-demo-compromised-web-01"
    Environment = "demo"
  }

  lifecycle {
    ignore_changes = [ami]
  }
}

resource "aws_ebs_volume" "test_target_data" {
  count             = var.deploy_test_target ? 1 : 0
  availability_zone = local.az
  size              = 1
  type              = "gp3"
  encrypted         = true
  tags              = { Name = "${local.name}-demo-web-data" }
}

resource "aws_volume_attachment" "test_target_data" {
  count        = var.deploy_test_target ? 1 : 0
  device_name  = "/dev/sdf"
  volume_id    = aws_ebs_volume.test_target_data[0].id
  instance_id  = aws_instance.test_target[0].id
  force_detach = true
}
