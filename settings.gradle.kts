rootProject.name = "deathtrap-backend"

include("packages:common-types")
include("packages:common-errors")
include("packages:common-response")
include("packages:common-db")
include("packages:common-crypto")
include("packages:common-audit")

include("apps:auth-service")
include("apps:locker-service")
include("apps:recovery-service")
include("apps:trigger-service")
include("apps:audit-service")
include("apps:sqs-consumer")
