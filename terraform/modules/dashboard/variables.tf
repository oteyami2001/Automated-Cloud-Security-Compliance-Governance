variable "name_prefix" {
  type = string
}

variable "region" {
  type = string
}

variable "function_names" {
  description = "Map of logical name -> Lambda function name."
  type        = map(string)
}

variable "processor_log_group" {
  type = string
}

variable "dlq_name" {
  type = string
}

variable "topic_arn" {
  type = string
}
