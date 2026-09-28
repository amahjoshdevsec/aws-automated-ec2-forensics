# Forensic workstation: Ubuntu 24.04 with Sleuth Kit, ClamAV and YARA.
# Reached only through SSM (Session Manager / Run Command). No SSH key pair,
# no inbound rules, IMDSv2 enforced, encrypted with the forensics CMK.

data "aws_ssm_parameter" "ubuntu" {
  name = "/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id"
}

data "aws_iam_policy_document" "ec2_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "workstation" {
  name               = "${local.name}-workstation"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
}

resource "aws_iam_role_policy_attachment" "workstation_ssm" {
  role       = aws_iam_role.workstation.name
  policy_arn = "arn:${local.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

data "aws_iam_policy_document" "workstation" {
  statement {
    sid       = "ReadTools"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.evidence.arn}/tools/*"]
  }
  statement {
    sid       = "ListTools"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.evidence.arn]
    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["tools/*"]
    }
  }
  statement {
    sid       = "WriteCaseResults"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.evidence.arn}/cases/*"]
  }
  statement {
    sid       = "UseEvidenceKey"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
    resources = [aws_kms_key.forensics.arn]
  }
  statement {
    sid       = "ScanOutputLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams", "logs:DescribeLogGroups"]
    resources = ["${aws_cloudwatch_log_group.scan.arn}:*", aws_cloudwatch_log_group.scan.arn]
  }
}

resource "aws_iam_role_policy" "workstation" {
  name   = "forensics-workstation"
  role   = aws_iam_role.workstation.id
  policy = data.aws_iam_policy_document.workstation.json
}

resource "aws_iam_instance_profile" "workstation" {
  name = "${local.name}-workstation"
  role = aws_iam_role.workstation.name
}

resource "aws_cloudwatch_log_group" "scan" {
  name              = "/${local.name}/scan-output"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.forensics.arn
}

resource "aws_instance" "workstation" {
  ami                         = var.workstation_ami_id != "" ? var.workstation_ami_id : data.aws_ssm_parameter.ubuntu.value
  instance_type               = var.workstation_instance_type
  subnet_id                   = aws_subnet.workstation.id
  vpc_security_group_ids      = [aws_security_group.workstation.id]
  iam_instance_profile        = aws_iam_instance_profile.workstation.name
  associate_public_ip_address = true # egress only; see README "production hardening" for private + endpoints
  monitoring                  = true
  ebs_optimized               = true
  user_data                   = file("${path.module}/../src/workstation/bootstrap.sh")
  user_data_replace_on_change = true

  metadata_options {
    http_tokens                 = "required"
    http_endpoint               = "enabled"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    volume_type = "gp3"
    volume_size = var.workstation_root_volume_gb
    encrypted   = true
    kms_key_id  = aws_kms_key.forensics.arn
  }

  tags = {
    Name = "${local.name}-workstation"
    Role = "ForensicWorkstation"
  }

  lifecycle {
    ignore_changes = [ami]
  }

  depends_on = [aws_iam_role_policy_attachment.workstation_ssm, aws_route_table_association.workstation]
}
