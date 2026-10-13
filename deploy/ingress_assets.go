package deploy

import _ "embed"

//go:embed setup-subscription-ingress-ssh.py
var SubscriptionIngressSSH string

//go:embed setup-bridge-subscription.py
var BridgeSubscriptionIngress string
