package admin

type Permission string

const (
	// Tenant permissions
	PermissionTenantRead   Permission = "tenant:read"
	PermissionTenantUpdate Permission = "tenant:update"

	// Project permissions
	PermissionProjectCreate Permission = "project:create"
	PermissionProjectRead   Permission = "project:read"
	PermissionProjectUpdate Permission = "project:update"
	PermissionProjectDelete Permission = "project:delete"

	// Member permissions
	PermissionMemberRead   Permission = "member:read"
	PermissionMemberCreate Permission = "member:create"
	PermissionMemberUpdate Permission = "member:update"
	PermissionMemberDelete Permission = "member:delete"

	// Agent permissions
	PermissionAgentRead   Permission = "agent:read"
	PermissionAgentCreate Permission = "agent:create"
	PermissionAgentUpdate Permission = "agent:update"
	PermissionAgentKill   Permission = "agent:kill"

	// API Key permissions
	PermissionAPIKeyCreate Permission = "apikey:create"
	PermissionAPIKeyRead   Permission = "apikey:read"
	PermissionAPIKeyRevoke Permission = "apikey:revoke"

	// Policy & Route permissions
	PermissionPolicyRead  Permission = "policy:read"
	PermissionPolicyWrite Permission = "policy:write"
	PermissionRouteRead   Permission = "route:read"
	PermissionRouteWrite  Permission = "route:write"

	// Wallet permissions
	PermissionWalletRead   Permission = "wallet:read"
	PermissionWalletAdjust Permission = "wallet:adjust"

	// Audit permissions
	PermissionAuditRead Permission = "audit:read"
)

var rolePermissions = map[MemberRole]map[Permission]bool{
	RoleOwner: {
		PermissionTenantRead:   true,
		PermissionTenantUpdate: true,
		PermissionProjectCreate: true,
		PermissionProjectRead:   true,
		PermissionProjectUpdate: true,
		PermissionProjectDelete: true,
		PermissionMemberRead:   true,
		PermissionMemberCreate: true,
		PermissionMemberUpdate: true,
		PermissionMemberDelete: true,
		PermissionAgentRead:   true,
		PermissionAgentCreate: true,
		PermissionAgentUpdate: true,
		PermissionAgentKill:   true,
		PermissionAPIKeyCreate: true,
		PermissionAPIKeyRead:   true,
		PermissionAPIKeyRevoke: true,
		PermissionPolicyRead:  true,
		PermissionPolicyWrite: true,
		PermissionRouteRead:   true,
		PermissionRouteWrite:  true,
		PermissionWalletRead:   true,
		PermissionWalletAdjust: true,
		PermissionAuditRead: true,
	},
	RoleAdmin: {
		PermissionTenantRead:   true,
		PermissionProjectCreate: true,
		PermissionProjectRead:   true,
		PermissionProjectUpdate: true,
		PermissionProjectDelete: true,
		PermissionMemberRead:   true,
		PermissionMemberCreate: true,
		PermissionMemberUpdate: true,
		PermissionMemberDelete: true,
		PermissionAgentRead:   true,
		PermissionAgentCreate: true,
		PermissionAgentUpdate: true,
		PermissionAgentKill:   true,
		PermissionAPIKeyCreate: true,
		PermissionAPIKeyRead:   true,
		PermissionAPIKeyRevoke: true,
		PermissionPolicyRead:  true,
		PermissionPolicyWrite: true,
		PermissionRouteRead:   true,
		PermissionRouteWrite:  true,
		PermissionWalletRead:   true,
		PermissionWalletAdjust: true,
		PermissionAuditRead: true,
	},
	RoleOperator: {
		PermissionTenantRead:   true,
		PermissionProjectRead:  true,
		PermissionMemberRead:   true,
		PermissionAgentRead:    true,
		PermissionAPIKeyRead:   true,
		PermissionPolicyRead:   true,
		PermissionRouteRead:    true,
		PermissionWalletRead:   true,
		PermissionAuditRead:    true,
	},
	RoleViewer: {
		PermissionTenantRead:  true,
		PermissionProjectRead: true,
		PermissionMemberRead:  true,
		PermissionAgentRead:   true,
		PermissionAPIKeyRead:  true,
		PermissionPolicyRead:  true,
		PermissionRouteRead:   true,
		PermissionWalletRead:  true,
		PermissionAuditRead:   true,
	},
}

// HasPermission checks if the role possesses the specified permission.
func HasPermission(role MemberRole, perm Permission) bool {
	perms, ok := rolePermissions[role]
	if !ok {
		return false
	}
	return perms[perm]
}

// EnforcePermission validates that member is active and possesses the permission.
func EnforcePermission(member *Member, perm Permission) error {
	if member == nil {
		return ErrPermissionDenied
	}
	if member.Status != MemberStatusActive {
		return ErrMemberDisabled
	}
	if !HasPermission(member.Role, perm) {
		return ErrPermissionDenied
	}
	return nil
}

// GetRolePermissions returns all permission string identifiers granted to a given role.
func GetRolePermissions(role MemberRole) []string {
	permsMap, ok := rolePermissions[role]
	if !ok {
		return []string{}
	}
	res := make([]string, 0, len(permsMap))
	for p, allowed := range permsMap {
		if allowed {
			res = append(res, string(p))
		}
	}
	return res
}

