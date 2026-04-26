package auth

// UserManager abstracts user storage (PostgreSQL via DBManager).
type UserManager interface {
	AddUser(kind, name string) (User, error)
	RenameUser(id, name string) (User, error)
	RemoveUser(id string) error
	PurgeUser(id string) error
	EnableUser(id string) error
	RotateUUID(id string) (string, error)
	RotateSocksPassword(id string) (string, error)
	List() []User
	ListAll() []User
	Lookup(id string) (User, bool)
	Close()
}
