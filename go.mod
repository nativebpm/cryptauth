module github.com/nativebpm/cryptauth

go 1.26

require (
	filippo.io/age v1.1.1
	github.com/nativebpm/totp v0.0.1
	golang.org/x/crypto v0.31.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/golang-jwt/jwt/v5 v5.3.1
	golang.org/x/sys v0.28.0 // indirect
)

replace github.com/nativebpm/totp => ../totp
