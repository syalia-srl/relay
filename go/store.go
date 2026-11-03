package relay

import (
	"errors"
	"os"
	"path/filepath"
	"unicode/utf8"
)

const stateVersion = 1

// Store keeps one side's state between runs: Load returns nil, nil on the first
// run and Save replaces the whole state.
type Store interface {
	Load() ([]byte, error)
	Save([]byte) error
}

// FileStore returns a store backed by one JSON file, written atomically at mode
// 0600 so the static key stays unreadable to other users.
func FileStore(path string) Store {
	return &fileStore{path: path}
}

type fileStore struct {
	path string
}

func (s *fileStore) Load() ([]byte, error) {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (s *fileStore) Save(data []byte) error {
	directory := filepath.Dir(s.path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, "."+filepath.Base(s.path)+".*.tmp")
	if err != nil {
		return err
	}
	name := temporary.Name()
	remove := true
	defer func() {
		if remove {
			_ = os.Remove(name)
		}
	}()
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, s.path); err != nil {
		return err
	}
	remove = false
	handle, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer handle.Close()
	return handle.Sync()
}

func loadState(store Store) (map[string]any, bool, error) {
	data, err := store.Load()
	if err != nil {
		return nil, false, err
	}
	if data == nil {
		return nil, true, nil
	}
	if !utf8.Valid(data) {
		return nil, false, errors.New("the state file is not JSON")
	}
	value, err := parseJSON(string(data))
	if err != nil {
		return nil, false, errors.New("the state file is not JSON")
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, false, errors.New("the state file is not a JSON object")
	}
	version, ok := asInteger(object["v"])
	if !ok || version != stateVersion {
		return nil, false, errors.New("the state file has an unknown version")
	}
	return object, false, nil
}
