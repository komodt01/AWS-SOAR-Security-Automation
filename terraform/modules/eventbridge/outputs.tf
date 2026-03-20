# EventBridge module has no outputs.
# All dependencies (state machine ARNs, invoke role) flow IN via variables.tf.
# Downstream modules (step-functions) expose their own ARNs directly.
