package model

import (
	"fmt"
	"strings"
)

func ParseSecretRef(value string) (SecretRef, error) {
	if err := validateOpaqueRef("secret_ref", value); err != nil {
		return "", err
	}
	return SecretRef(value), nil
}

func NewSecretRef(kind, id string) (SecretRef, error) {
	return ParseSecretRef(kind + ":" + id)
}

func (reference SecretRef) String() string {
	return string(reference)
}

func (reference SecretRef) Parts() (kind, id string, err error) {
	if _, err := ParseSecretRef(string(reference)); err != nil {
		return "", "", err
	}
	kind, id, found := strings.Cut(string(reference), ":")
	if !found {
		return "", "", fmt.Errorf("secret reference has no separator")
	}
	return kind, id, nil
}
