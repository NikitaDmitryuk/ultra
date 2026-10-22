package deployansible

// DeploymentBackgroundReady is the read-only systemd schedule gate. Background
// jobs must wait for the authoritative deployment to complete, even when its
// supervisor has exited. It neither creates the namespace nor acquires a lease.
func DeploymentBackgroundReady() error {
	return checkDeploymentExecutionAdmission(executionFenceDirectory(""), nil)
}
