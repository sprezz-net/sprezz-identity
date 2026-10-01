package admin

import (
	"strconv"
	"time"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"
)

// UserRow is one line of the user list.
type UserRow struct {
	User          model.UserProfile
	PartitionName string
}

// UserListProps is everything the user list renders. Filters are applied on the server.
type UserListProps struct {
	ActiveTenant model.Tenant
	Rows         []UserRow
	Partitions   []model.Partition
	Msg          string
	Query        string
	Status       string
	PartitionID  int64
}

// UserPageProps is everything the user detail page renders.
type UserPageProps struct {
	ActiveTenant  model.Tenant
	Detail        *port.UserDetail
	PartitionName string
	ActingUserID  string
	Msg           string
	Sections      map[string]SectionResult
}

// Section returns the result for a section, or the zero value when it was not just saved.
func (p UserPageProps) Section(name string) SectionResult {
	return p.Sections[name]
}

// IsSelf reports whether the page shows the administrator who is looking at it.
func (p UserPageProps) IsSelf() bool {
	return p.Detail.User.ID.String() == p.ActingUserID
}

func usersBase() string {
	return port.RouteAdmin + port.RouteAdminUsers
}

// userURL addresses a user by partition and ID, so the lookup is always scoped to the partition.
func userURL(partitionID int64, id string) string {
	return usersBase() + "/" + strconv.FormatInt(partitionID, 10) + "/" + id
}

func userSectionAction(partitionID int64, id, section string) string {
	return userURL(partitionID, id) + "/" + section
}

func userStatusLabel(u model.UserProfile) (string, string) {
	if u.Blocked {
		return "Blocked", "locked"
	}
	switch u.LifecycleState {
	case model.LifecycleActivated:
		return "Active", "active"
	case model.LifecycleRequested:
		return "Awaiting approval", "warning"
	case model.LifecycleDeactivated:
		return "Deactivated", "inactive"
	default:
		return "Not activated", "warning"
	}
}

func lifecycleLabel(state model.ProfileLifecycleState) string {
	switch state {
	case model.LifecycleActivated:
		return "Active"
	case model.LifecycleRequested:
		return "Awaiting approval"
	case model.LifecycleInvited:
		return "Invited"
	case model.LifecycleCreated:
		return "Created, not activated"
	case model.LifecycleDeactivated:
		return "Deactivated"
	default:
		return string(state)
	}
}

func formatInstant(t time.Time) string {
	if t.IsZero() {
		return "unknown"
	}
	return t.UTC().Format("2006-01-02 15:04 MST")
}

func formatInstantPtr(t *time.Time) string {
	if t == nil {
		return "never"
	}
	return formatInstant(*t)
}

// UserDeleteProps builds the danger zone of a user.
func UserDeleteProps(props UserPageProps) ConfirmDeleteProps {
	p := ConfirmDeleteProps{
		Action:   userURL(props.Detail.User.PartitionID, props.Detail.User.ID.String()),
		Expected: props.Detail.User.PreferredUsername,
		Noun:     "user",
		Warning:  "Deleting a user removes the account and every sign-in method. It cannot be undone.",
	}
	if props.IsSelf() {
		p.Blocked = "You cannot delete the account you are signed in with."
	}
	return p
}

// UserNewProps drives the add form.
type UserNewProps struct {
	ActiveTenant model.Tenant
	Partitions   []model.Partition
	Errors       map[string]string
	Error        string
	Values       map[string]string
}

// V returns the value typed before a validation error.
func (p UserNewProps) V(name string) string {
	return p.Values[name]
}
