package deployansible

import "errors"

// This API classifies a preserved failure for canonical replacement. It neither
// observes a timeout (which may publish evidence) nor retires a generation.
// The caller must validate the frozen target scope and independently prove
// quiescence; only AbandonExecutionFence can perform the retirement.
func PreflightExecutionReplacement() (*ExecutionFence, error) {
	if !executionNamespaceFixture() {
		if err := executionContainmentPreflight(); err != nil {
			return nil, err
		}
	}
	root := executionFenceDirectory("")
	if err := preflightExecutionAdmission(root); err == nil {
		return nil, nil
	} else if !errors.Is(err, ErrExecutionFenced) {
		return nil, err
	}
	fence, err := inspectExecutionFence(root)
	if err != nil {
		return nil, err
	}
	if fence == nil {
		return nil, ErrExecutionFenced
	}
	if err = verifyFailedGeneration(root, *fence); err != nil {
		return nil, err
	}
	return fence, nil
}
