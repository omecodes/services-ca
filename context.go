package sca

import (
	"context"
	"crypto"
	"crypto/x509"
)

type ctxCert struct{}
type ctxKey struct{}
type ctxManager struct{}

func ContextWithManager(parent context.Context, manager CredentialsManager) context.Context {
	return context.WithValue(parent, ctxManager{}, manager)
}

func ContextWithCert(parent context.Context, cert *x509.Certificate) context.Context {
	return context.WithValue(parent, ctxCert{}, cert)
}

func ContextWithKey(parent context.Context, key crypto.PrivateKey) context.Context {
	return context.WithValue(parent, ctxKey{}, key)
}

func manager(ctx context.Context) CredentialsManager {
	o := ctx.Value(ctxManager{})
	if o == nil {
		return nil
	}
	return o.(CredentialsManager)
}

func certificate(ctx context.Context) *x509.Certificate {
	o := ctx.Value(ctxCert{})
	if o == nil {
		return nil
	}
	return o.(*x509.Certificate)
}

func key(ctx context.Context) crypto.PrivateKey {
	o := ctx.Value(ctxKey{})
	if o == nil {
		return nil
	}
	return o.(crypto.PrivateKey)
}
