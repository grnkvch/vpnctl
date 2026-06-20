package domain

type Server struct {
	ID                  string
	Name                string
	PublicEndpoint      string
	SSHHost             string
	SSHUser             string
	WireGuardInterface  string
	WireGuardPort       int
	WireGuardSubnet     string
	DNSServers          []string
	AllowedClientRoutes []string
}
