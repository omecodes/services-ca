package sca

type CredentialsManager interface {
	GetSecret(string) (string, error)
}

type CredentialsManagerFunc func(string) (string, error)

func (f CredentialsManagerFunc) GetSecret(name string) (string, error) {
	return f(name)
}
