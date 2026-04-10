package auth

// UserManager abstracts user storage (PostgreSQL via DBManager).
type UserManager interface {
	AddUser(name string) (User, error)
	RenameUser(id, name string) (User, error)
	RemoveUser(id string) error
	List() []User
	Lookup(id string) (User, bool)
	Close()
}
