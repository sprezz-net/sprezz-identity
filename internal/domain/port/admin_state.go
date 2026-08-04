package port

type AdminState interface {
	GetEphemeralSecret() string
}
