package portmock

//go:generate go run github.com/gojuno/minimock/v3/cmd/minimock@v3.4.7 -i sprezz-identity/internal/domain/port.Auth -o auth_mock.go
//go:generate go run github.com/gojuno/minimock/v3/cmd/minimock@v3.4.7 -i sprezz-identity/internal/domain/port.Crypto -o crypto_mock.go
//go:generate go run github.com/gojuno/minimock/v3/cmd/minimock@v3.4.7 -i sprezz-identity/internal/domain/port.Storage -o storage_mock.go
//go:generate go run github.com/gojuno/minimock/v3/cmd/minimock@v3.4.7 -i sprezz-identity/internal/domain/port.Event -o event_mock.go
