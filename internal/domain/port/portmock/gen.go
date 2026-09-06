package portmock

//go:generate go run github.com/gojuno/minimock/v3/cmd/minimock@v3.4.7 -i sprezz-identity/internal/domain/port.AuthUseCase -o auth_mock.go -n AuthMock
//go:generate go run github.com/gojuno/minimock/v3/cmd/minimock@v3.4.7 -i sprezz-identity/internal/domain/port.Crypto -o crypto_mock.go
//go:generate go run github.com/gojuno/minimock/v3/cmd/minimock@v3.4.7 -i sprezz-identity/internal/domain/port.Storage -o storage_mock.go
//go:generate go run github.com/gojuno/minimock/v3/cmd/minimock@v3.4.7 -i sprezz-identity/internal/domain/port.AdminStorage -o admin_storage_mock.go
//go:generate go run github.com/gojuno/minimock/v3/cmd/minimock@v3.4.7 -i sprezz-identity/internal/domain/port.AdminApplicationUseCase -o admin_application_usecase_mock.go -n AdminApplicationUseCaseMock
//go:generate go run github.com/gojuno/minimock/v3/cmd/minimock@v3.4.7 -i sprezz-identity/internal/domain/port.Event -o event_mock.go
//go:generate go run github.com/gojuno/minimock/v3/cmd/minimock@v3.4.7 -i sprezz-identity/internal/domain/port.LogoutNotifier -o logout_notifier_mock.go
//go:generate go run github.com/gojuno/minimock/v3/cmd/minimock@v3.4.7 -i sprezz-identity/internal/domain/port.TenantUseCase -o tenant_usecase_mock.go -n TenantUseCaseMock
//go:generate go run github.com/gojuno/minimock/v3/cmd/minimock@v3.4.7 -i sprezz-identity/internal/domain/port.FederatedLoginUseCase -o federated_login_usecase_mock.go -n FederatedLoginUseCaseMock
//go:generate go run github.com/gojuno/minimock/v3/cmd/minimock@v3.4.7 -i sprezz-identity/internal/domain/port.SSOSessionUseCase -o sso_session_usecase_mock.go -n SSOSessionUseCaseMock
//go:generate go run github.com/gojuno/minimock/v3/cmd/minimock@v3.4.7 -i sprezz-identity/internal/domain/port.UserProfileUseCase -o user_profile_usecase_mock.go -n UserProfileUseCaseMock
//go:generate go run github.com/gojuno/minimock/v3/cmd/minimock@v3.4.7 -i sprezz-identity/internal/domain/port.UserRegistrationUseCase -o user_registration_usecase_mock.go -n UserRegistrationUseCaseMock
//go:generate go run github.com/gojuno/minimock/v3/cmd/minimock@v3.4.7 -i sprezz-identity/internal/domain/port.LocalAuthUseCase -o local_auth_usecase_mock.go -n LocalAuthUseCaseMock
//go:generate go run github.com/gojuno/minimock/v3/cmd/minimock@v3.4.7 -i sprezz-identity/internal/domain/port.FederationClient -o federation_client_mock.go -n FederationClientMock
//go:generate go run github.com/gojuno/minimock/v3/cmd/minimock@v3.4.7 -i sprezz-identity/internal/domain/port.AdminLogonUseCase -o admin_logon_usecase_mock.go -n AdminLogonUseCaseMock
