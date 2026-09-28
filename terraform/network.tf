# Dedicated, isolated VPC for forensic analysis.
# - Workstation subnet: no inbound rules at all; egress only to 80/443 for OS
#   packages, ClamAV signatures and AWS APIs (SSM, S3 via gateway endpoint).
# - Workload subnet (demo only): hosts the test target with NO internet route.

resource "aws_vpc" "forensics" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "${local.name}-vpc" }
}

# Lock down the default security group (CIS 5.4).
resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.forensics.id
  tags   = { Name = "${local.name}-default-deny" }
}

resource "aws_internet_gateway" "forensics" {
  vpc_id = aws_vpc.forensics.id
  tags   = { Name = "${local.name}-igw" }
}

resource "aws_subnet" "workstation" {
  vpc_id                  = aws_vpc.forensics.id
  cidr_block              = var.workstation_subnet_cidr
  availability_zone       = local.az
  map_public_ip_on_launch = false
  tags                    = { Name = "${local.name}-workstation" }
}

resource "aws_route_table" "workstation" {
  vpc_id = aws_vpc.forensics.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.forensics.id
  }
  tags = { Name = "${local.name}-workstation-rt" }
}

resource "aws_route_table_association" "workstation" {
  subnet_id      = aws_subnet.workstation.id
  route_table_id = aws_route_table.workstation.id
}

resource "aws_subnet" "workload" {
  count             = var.deploy_test_target ? 1 : 0
  vpc_id            = aws_vpc.forensics.id
  cidr_block        = var.workload_subnet_cidr
  availability_zone = local.az
  tags              = { Name = "${local.name}-demo-workload" }
}

resource "aws_route_table" "workload" {
  count  = var.deploy_test_target ? 1 : 0
  vpc_id = aws_vpc.forensics.id
  tags   = { Name = "${local.name}-demo-workload-rt (no internet)" }
}

resource "aws_route_table_association" "workload" {
  count          = var.deploy_test_target ? 1 : 0
  subnet_id      = aws_subnet.workload[0].id
  route_table_id = aws_route_table.workload[0].id
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.forensics.id
  service_name      = "com.amazonaws.${local.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = concat([aws_route_table.workstation.id], aws_route_table.workload[*].id)
  tags              = { Name = "${local.name}-s3-endpoint" }
}

resource "aws_security_group" "workstation" {
  name        = "${local.name}-workstation"
  description = "Forensic workstation - no inbound; HTTPS/HTTP egress only"
  vpc_id      = aws_vpc.forensics.id
  tags        = { Name = "${local.name}-workstation" }
}

resource "aws_vpc_security_group_egress_rule" "workstation_https" {
  security_group_id = aws_security_group.workstation.id
  description       = "HTTPS to AWS APIs, ClamAV signature mirrors, snap store"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_vpc_security_group_egress_rule" "workstation_http" {
  security_group_id = aws_security_group.workstation.id
  description       = "HTTP to Ubuntu package mirrors (packages are GPG signed)"
  ip_protocol       = "tcp"
  from_port         = 80
  to_port           = 80
  cidr_ipv4         = "0.0.0.0/0"
}

# ---------------------------------------------------------------- flow logs
resource "aws_cloudwatch_log_group" "flow_logs" {
  count             = var.enable_flow_logs ? 1 : 0
  name              = "/${local.name}/vpc-flow-logs"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.forensics.arn
}

data "aws_iam_policy_document" "flow_logs_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["vpc-flow-logs.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_iam_role" "flow_logs" {
  count              = var.enable_flow_logs ? 1 : 0
  name               = "${local.name}-flow-logs"
  assume_role_policy = data.aws_iam_policy_document.flow_logs_assume.json
}

resource "aws_iam_role_policy" "flow_logs" {
  count  = var.enable_flow_logs ? 1 : 0
  name   = "write-flow-logs"
  role   = aws_iam_role.flow_logs[0].id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"]
      Resource = "${aws_cloudwatch_log_group.flow_logs[0].arn}:*"
    }]
  })
}

resource "aws_flow_log" "forensics" {
  count           = var.enable_flow_logs ? 1 : 0
  vpc_id          = aws_vpc.forensics.id
  traffic_type    = "ALL"
  iam_role_arn    = aws_iam_role.flow_logs[0].arn
  log_destination = aws_cloudwatch_log_group.flow_logs[0].arn
}
