package kafka.authz

import rego.v1

# By default, deny requests
default allow := false

# Allow the action if the user is granted permission to perform the action.
allow if {
	some permission
	user_is_granted[permission]

	# Check if the permission permits the action.
	input.action == permission.action
	input.topic == permission.topic
}

# Helper rule to extract the payload from the JWT
payload := decode_jwt(input.jwt)

# Decode the JWT and extract the payload
decode_jwt(jwt) := payload if {
	[_, payload, _] := io.jwt.decode(jwt)
}

# user_is_granted is a set of permissions for the user identified in the request.
user_is_granted[permission] if {
	some i, j

	# `role` assigned an element of the user_roles for this user...
	role := payload.realm_access.roles[i]

	# `permission` assigned a single permission from the permissions list for 'role'...
	permission := role_permissions[role][j]
}

# Data structure for role permissions
# This would typically be defined in your input data, but for illustration, we can define it here.
# In a real use case, this should be provided in the data input or an external source.
role_permissions := {
	"kafka-client-producer": [{"action": "produce", "topic": "myTopic"}],
	"EMS": [{"action": "consume", "topic": "myTopic"}],
	"Admin": [
		{"action": "produce", "topic": "myTopic"},
		{"action": "consume", "topic": "myTopic"},
	],
}
