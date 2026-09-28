variable "region" {
  description = "AWS region to deploy the forensics stack into. Instances are investigated in this region."
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Prefix for resource names."
  type        = string
  default     = "ec2-forensics"

  validation {
    condition     = can(regex("^[a-z0-9-]{3,24}$", var.project_name))
    error_message = "project_name must be 3-24 lowercase letters, digits or dashes."
  }
}

variable "approver_email" {
  description = "Email address that receives approval requests (you must confirm the SNS subscription email)."
  type        = string

  validation {
    condition     = can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.approver_email))
    error_message = "approver_email must be a valid email address."
  }
}

variable "notification_email" {
  description = "Email address for report / failure notifications. Defaults to approver_email."
  type        = string
  default     = null
}

variable "tags" {
  description = "Extra tags applied to every resource."
  type        = map(string)
  default     = {}
}

# ---------------------------------------------------------------- network
variable "vpc_cidr" {
  description = "CIDR block for the isolated forensics VPC."
  type        = string
  default     = "10.40.0.0/16"
}

variable "workstation_subnet_cidr" {
  description = "Subnet for the forensic workstation."
  type        = string
  default     = "10.40.1.0/24"
}

variable "workload_subnet_cidr" {
  description = "Subnet for the demo test target (only used when deploy_test_target = true)."
  type        = string
  default     = "10.40.2.0/24"
}

variable "enable_flow_logs" {
  description = "Capture VPC flow logs for the forensics VPC."
  type        = bool
  default     = true
}

# ---------------------------------------------------------------- workstation
variable "workstation_instance_type" {
  description = "Instance type for the forensic workstation. ClamAV needs ~1.5 GB RAM."
  type        = string
  default     = "t3.medium"
}

variable "workstation_root_volume_gb" {
  description = "Root volume size for the workstation (working space for timelines and artifacts)."
  type        = number
  default     = 40
}

variable "workstation_ami_id" {
  description = "Optional AMI override (for example a hardened golden image or SANS SIFT). Empty uses latest Ubuntu 24.04."
  type        = string
  default     = ""
}

# ---------------------------------------------------------------- workflow
variable "approval_timeout_seconds" {
  description = "How long an approval request stays valid before the case fails."
  type        = number
  default     = 86400
}

variable "scan_timeout_seconds" {
  description = "Maximum run time for the forensic scan command on the workstation."
  type        = number
  default     = 7200
}

variable "max_volumes_per_instance" {
  description = "Safety limit on the number of EBS volumes collected per case."
  type        = number
  default     = 4
}

variable "delete_intermediate_snapshots" {
  description = "Delete the intermediate (non-evidence) snapshots after the evidence copy completes."
  type        = bool
  default     = true
}

# ---------------------------------------------------------------- evidence storage
variable "evidence_retention_days" {
  description = "Days before evidence objects transition to Glacier Deep Archive."
  type        = number
  default     = 90
}

variable "enable_object_lock" {
  description = "Enable S3 Object Lock (governance mode) on the evidence bucket. Leave false for personal testing so teardown is easy."
  type        = bool
  default     = false
}

variable "object_lock_days" {
  description = "Default Object Lock retention in days (when enable_object_lock = true)."
  type        = number
  default     = 365
}

variable "force_destroy_evidence_bucket" {
  description = "Allow terraform destroy to delete a non-empty evidence bucket. true for labs, false for production."
  type        = bool
  default     = true
}

variable "kms_deletion_window_days" {
  description = "KMS key deletion window."
  type        = number
  default     = 7
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention."
  type        = number
  default     = 365
}

# ---------------------------------------------------------------- triggers / multi-account
variable "enable_guardduty_trigger" {
  description = "Start an investigation automatically for GuardDuty EC2 findings at or above guardduty_min_severity (GuardDuty must already be enabled). Approval is still required."
  type        = bool
  default     = false
}

variable "guardduty_min_severity" {
  description = "Minimum GuardDuty severity (0-10) that triggers an investigation."
  type        = number
  default     = 7
}

variable "member_account_ids" {
  description = "Workload account IDs this forensics account may investigate (each needs terraform/modules/member-account-role). Empty = single-account mode."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for a in var.member_account_ids : can(regex("^[0-9]{12}$", a))])
    error_message = "member_account_ids must be 12 digit account ids."
  }
}

variable "member_role_name" {
  description = "Name of the responder role deployed in each member account."
  type        = string
  default     = "ForensicsResponderRole"
}

# ---------------------------------------------------------------- demo
variable "deploy_test_target" {
  description = "Deploy a deliberately 'compromised' (inert) EC2 instance to test the pipeline end to end."
  type        = bool
  default     = true
}
