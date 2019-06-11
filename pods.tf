resource "aws_iam_role" "k8s_pods_iam_role" {
  count                 = "${var.manage_worker_iam_resources ? 1 : 0}"
  name                  = "${aws_eks_cluster.this.name}-iam-role"
  assume_role_policy    = "${data.aws_iam_policy_document.k8s_pods_assume_role_policy.json}"
  permissions_boundary  = "${var.permissions_boundary}"
  path                  = "${var.iam_path}"
  force_detach_policies = true
}

resource "aws_iam_policy" "k8s_pods_iam_policy" {
  count       = "${var.manage_worker_iam_resources ? 1 : 0}"
  name        = "k8s-pods-${aws_eks_cluster.this.name}"
  description = "EKS pods policy for cluster ${aws_eks_cluster.this.name}"
  policy      = "${data.aws_iam_policy_document.k8s_pods_policy.json}"
  path        = "${var.iam_path}"
}

resource "aws_iam_role_policy_attachment" "k8s_pods" {
  count      = "${var.manage_worker_iam_resources ? 1 : 0}"
  policy_arn = "${aws_iam_policy.k8s_pods_iam_policy.arn}"
  role       = "${aws_iam_role.k8s_pods_iam_role.name}"
}

resource "aws_iam_policy" "worker_autoscaling" {
  count       = "${var.manage_worker_iam_resources ? 1 : 0}"
  name        = "eks-worker-autoscaling-${aws_eks_cluster.this.name}"
  description = "EKS worker node autoscaling policy for cluster ${aws_eks_cluster.this.name}"
  policy      = "${data.aws_iam_policy_document.worker_autoscaling.json}"
  path        = "${var.iam_path}"
}

resource "aws_iam_policy" "route53_external_dns" {
  count       = "${var.manage_worker_iam_resources ? 1 : 0}"
  name        = "eks-worker-external-dns-${aws_eks_cluster.this.name}"
  description = "EKS worker node external dns policy for cluster ${aws_eks_cluster.this.name}"
  policy      = "${data.aws_iam_policy_document.worker_external_dns.json}"
  path        = "${var.iam_path}"
}

resource "aws_iam_role_policy_attachment" "workers_autoscaling" {
  count      = "${var.manage_worker_iam_resources ? 1 : 0}"
  policy_arn = "${aws_iam_policy.worker_autoscaling.arn}"
  role       = "${aws_iam_role.k8s_pods_iam_role.name}"
}

resource "aws_iam_role_policy_attachment" "workers_workers_dns" {
  count      = "${var.manage_worker_iam_resources ? 1 : 0}"
  policy_arn = "${aws_iam_policy.route53_external_dns.arn}"
  role       = "${aws_iam_role.k8s_pods_iam_role.name}"
}

resource "aws_iam_role_policy_attachment" "pods_AmazonEKSWorkerNodePolicy" {
  count      = "${var.manage_worker_iam_resources ? 1 : 0}"
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = "${aws_iam_role.k8s_pods_iam_role.name}"
}

resource "aws_iam_role_policy_attachment" "pods_AmazonEKS_CNI_Policy" {
  count      = "${var.manage_worker_iam_resources ? 1 : 0}"
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = "${aws_iam_role.k8s_pods_iam_role.name}"
}

data "aws_iam_policy_document" "k8s_pods_assume_role_policy" {
  statement {
    sid = "EKSWorkerAssumeRole"

    actions = [
      "sts:AssumeRole",
    ]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "k8s_pods_policy" {
  statement {
    sid    = "eksWorkerAcm"
    effect = "Allow"

    actions = [
      "acm:DescribeCertificate",
      "acm:ListCertificates",
      "acm:GetCertificate",
    ]

    resources = ["*"]
  }

  statement {
    sid    = "eksWorkerEc2"
    effect = "Allow"

    actions = [
      "ec2:AuthorizeSecurityGroupIngress",
      "ec2:CreateSecurityGroup",
      "ec2:CreateTags",
      "ec2:DeleteTags",
      "ec2:DeleteSecurityGroup",
      "ec2:DescribeAccountAttributes",
      "ec2:DescribeAddresses",
      "ec2:DescribeInstances",
      "ec2:DescribeInstanceStatus",
      "ec2:DescribeInternetGateways",
      "ec2:DescribeNetworkInterfaces",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeSubnets",
      "ec2:DescribeTags",
      "ec2:DescribeVpcs",
      "ec2:DescribeRouteTables",
      "ec2:DescribeVpcs",
      "ec2:ModifyInstanceAttribute",
      "ec2:ModifyNetworkInterfaceAttribute",
      "ec2:RevokeSecurityGroupIngress",
      "ec2:CreateNetworkInterface",
      "ec2:DeleteNetworkInterface",
      "ec2:DescribeNetworkInterfaceAttribute",
    ]

    resources = ["*"]
  }

  statement {
    sid    = "eksWorkerELB"
    effect = "Allow"

    actions = [
      "cloudformation:*",
      "elasticloadbalancing:AddListenerCertificates",
      "elasticloadbalancing:AddTags",
      "elasticloadbalancing:CreateListener",
      "elasticloadbalancing:CreateLoadBalancer",
      "elasticloadbalancing:CreateRule",
      "elasticloadbalancing:CreateTargetGroup",
      "elasticloadbalancing:DeleteListener",
      "elasticloadbalancing:DeleteLoadBalancer",
      "elasticloadbalancing:DeleteRule",
      "elasticloadbalancing:DeleteTargetGroup",
      "elasticloadbalancing:DeregisterTargets",
      "elasticloadbalancing:DescribeListenerCertificates",
      "elasticloadbalancing:DescribeListeners",
      "elasticloadbalancing:DescribeLoadBalancers",
      "elasticloadbalancing:DescribeLoadBalancerAttributes",
      "elasticloadbalancing:DescribeRules",
      "elasticloadbalancing:DescribeSSLPolicies",
      "elasticloadbalancing:DescribeTags",
      "elasticloadbalancing:DescribeTargetGroups",
      "elasticloadbalancing:DescribeTargetGroupAttributes",
      "elasticloadbalancing:DescribeTargetHealth",
      "elasticloadbalancing:ModifyListener",
      "elasticloadbalancing:ModifyLoadBalancerAttributes",
      "elasticloadbalancing:ModifyRule",
      "elasticloadbalancing:ModifyTargetGroup",
      "elasticloadbalancing:ModifyTargetGroupAttributes",
      "elasticloadbalancing:RegisterTargets",
      "elasticloadbalancing:RemoveListenerCertificates",
      "elasticloadbalancing:RemoveTags",
      "elasticloadbalancing:SetIpAddressType",
      "elasticloadbalancing:SetSecurityGroups",
      "elasticloadbalancing:SetSubnets",
      "elasticloadbalancing:SetWebACL",
      "elasticloadbalancingv2:*",
      "elasticfilesystem:*",
    ]

    resources = [
      "*",
    ]
  }

  statement {
    sid    = "eksWorkerwIamService"
    effect = "Allow"

    actions = [
      "iam:CreateServiceLinkedRole",
      "iam:GetServerCertificate",
      "iam:ListServerCertificates",
    ]

    resources = ["*"]
  }

  statement {
    sid    = "eksWorkerUSerPool"
    effect = "Allow"

    actions = [
      "cognito-idp:DescribeUserPoolClient",
    ]

    resources = ["*"]
  }

  statement {
    sid    = "eksWorkerWaf"
    effect = "Allow"

    actions = [
      "waf-regional:GetWebACLForResource",
      "waf-regional:GetWebACL",
      "waf-regional:AssociateWebACL",
      "waf-regional:DisassociateWebACL",
      "waf:GetWebACL",
    ]

    resources = ["*"]
  }

  statement {
    sid    = "eksWorkerTag"
    effect = "Allow"

    actions = [
      "tag:GetResources",
      "tag:TagResources",
    ]

    resources = ["*"]
  }
}

data "aws_iam_policy_document" "worker_external_dns" {
  statement {
    sid    = "eksWorkerExternalDns"
    effect = "Allow"

    actions = [
      "route53:ChangeResourceRecordSets",
    ]

    resources = ["*"]
  }

  statement {
    sid    = "eksWorkerListDns"
    effect = "Allow"

    actions = [
      "route53:ListHostedZones",
      "route53:ListResourceRecordSets",
    ]

    resources = ["*"]
  }
}

data "aws_iam_policy_document" "worker_autoscaling" {
  statement {
    sid    = "eksWorkerAutoscalingAll"
    effect = "Allow"

    actions = [
      "autoscaling:DescribeAutoScalingGroups",
      "autoscaling:DescribeAutoScalingInstances",
      "autoscaling:DescribeLaunchConfigurations",
      "autoscaling:DescribeTags",
      "ec2:DescribeLaunchTemplateVersions",
    ]

    resources = ["*"]
  }

  statement {
    sid    = "eksWorkerAutoscalingOwn"
    effect = "Allow"

    actions = [
      "autoscaling:SetDesiredCapacity",
      "autoscaling:TerminateInstanceInAutoScalingGroup",
      "autoscaling:UpdateAutoScalingGroup",
      "autoscaling:AttachLoadBalancers",
      "autoscaling:DetachLoadBalancers",
      "autoscaling:DetachLoadBalancerTargetGroups",
      "autoscaling:AttachLoadBalancerTargetGroups",
      "autoscaling:DescribeLoadBalancerTargetGroups",
    ]

    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "autoscaling:ResourceTag/kubernetes.io/cluster/${aws_eks_cluster.this.name}"
      values   = ["owned", "shared"]
    }

    condition {
      test     = "StringEquals"
      variable = "autoscaling:ResourceTag/k8s.io/cluster-autoscaler/enabled"
      values   = ["true"]
    }
  }
}
