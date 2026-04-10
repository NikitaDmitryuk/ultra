package auth

// UserManager abstracts user storage so the admin API and relay core
// can work with either the JSON-file backend (Manager) or PostgreSQL (DBManager).
type UserManager interface {
	AddUser(name string) (User, error)
	RenameUser(id, name string) (User, error)
	RemoveUser(id string) error
	List() []User
	Lookup(id string) (User, bool)
	Close()
}
