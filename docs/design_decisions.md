# Design Decisions

## Cost Governance

### Decision
Implemented AWS Budgets and billing alarms and added documented teardown procedures for all deployed infrastructure.

### Context
An earlier cloud project revealed that monitoring costs alone does not guarantee all deployed resources have been accounted for during shutdown.

### Tradeoffs
Pros
- Reduces risk of orphaned cloud resources
- Improves operational governance
- Lowers long-term operational costs
- Provides repeatable project lifecycle management

Cons
- Additional documentation effort
- Extra verification steps before project completion

### Architectural Principle

Cost governance is part of cloud architecture, not an operational afterthought.

Monitoring detects unexpected spend.
Lifecycle governance prevents it.
