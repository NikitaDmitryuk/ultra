package auth

// UserManager abstracts user storage (PostgreSQL via DBManager).
type UserManager interface {
	AddUser(name string) (User, error)
	RenameUser(id, name string) (User, error)
	SetNote(id, note string) (User, error)
	RemoveUser(id string) error
	EnableUser(id string) error
	RotateUUID(id string) (string, error)
	List() []User
	ListAll() []User
	Lookup(id string) (User, bool)
	Close()
}
