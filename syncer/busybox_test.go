package syncer

import (
	"context"
	"strings"
	"testing"

	"github.com/cybozu-go/etcdpasswd"
	"github.com/google/go-cmp/cmp"
)

func MockedRunner() (CmdRunner, **[]string) {
	executed := &[]string{}
	return func(ctx context.Context, name string, args ...string) error {
		fullCommand := make([]string, 0, len(args)+1)
		fullCommand = append(fullCommand, name)
		fullCommand = append(fullCommand, args...)
		*executed = append(*executed, strings.Join(fullCommand, " "))
		return nil
	}, &executed
}

func TestLookupUser(t *testing.T) {
	ctx := context.Background()

	runner, _ := MockedRunner()
	subject := BusyboxSyncer{
		Run: runner,
	}

	user, err := subject.LookupUser(ctx, "nonexisting")
	if err != nil {
		t.Fatal(err)
	}
	if user != nil {
		t.Errorf(`Expected nonexisting user to not be defined, but got %#v`, user)
	}

	user, err = subject.LookupUser(ctx, "root")
	if err != nil {
		t.Fatal(err)
	}
	expectedUser := etcdpasswd.User{
		Name:        "root",
		UID:         0,
		DisplayName: "root",
		Groups:      []string{},
		Shell:       "/bin/bash",
		Group:       "root",
	}
	if !cmp.Equal(expectedUser, *user) {
		t.Errorf(`Expected %#v, but got %#v`, expectedUser, user)
	}
}

func TestLookupGroup(t *testing.T) {
	ctx := context.Background()

	runner, _ := MockedRunner()
	subject := BusyboxSyncer{
		Run: runner,
	}

	group, err := subject.LookupGroup(ctx, "nonexisting")
	if err != nil {
		t.Fatal(err)
	}
	if group != nil {
		t.Errorf(`Expected nonexisting group to not be defined, but got %#v`, group)
	}

	group, err = subject.LookupGroup(ctx, "root")
	if err != nil {
		t.Fatal(err)
	}
	expectedGroup := etcdpasswd.Group{
		Name: "root",
		GID:  0,
	}
	if !cmp.Equal(expectedGroup, *group) {
		t.Errorf(`Expected %#v, but got %#v`, expectedGroup, group)
	}
}

func TestAddUser(t *testing.T) {
	ctx := context.Background()

	runner, actualCmds := MockedRunner()

	subject := BusyboxSyncer{
		Run: runner,
	}

	err := subject.AddUser(ctx, &etcdpasswd.User{
		Name:        "newuser",
		Group:       "usersgroup",
		DisplayName: "displayName",
		UID:         1000,
		Shell:       "/sbin/nologin",
		Groups:      []string{"group1", "group2"},
	})

	if err != nil {
		t.Fatal(err)
	}

	expectedCmds := []string{"adduser -c displayName -G usersgroup -s /sbin/nologin -u 1000 -D newuser", "addgroup newuser group1", "addgroup newuser group2"}

	if !cmp.Equal(expectedCmds, **actualCmds) {
		t.Errorf(`Expected the correct commands to be executed, but got %#v`, **actualCmds)
	}
}

func TestAddUserExistingUser(t *testing.T) {
	ctx := context.Background()

	runner, _ := MockedRunner()

	subject := BusyboxSyncer{
		Run: runner,
	}

	err := subject.AddUser(ctx, &etcdpasswd.User{
		Name:        "root",
		Group:       "root",
		DisplayName: "displayName",
		UID:         0,
		Shell:       "/sbin/nologin",
		Groups:      []string{},
	})

	if err == nil {
		t.Errorf(`Expected an error to be thrown when adding existing user`)
	}
}

func TestRemoveUser(t *testing.T) {
	ctx := context.Background()

	runner, actualCmds := MockedRunner()

	subject := BusyboxSyncer{
		Run: runner,
	}

	err := subject.RemoveUser(ctx, "root")

	if err != nil {
		t.Fatal(err)
	}

	expectedCmds := []string{"deluser --remove-home root"}

	if !cmp.Equal(expectedCmds, **actualCmds) {
		t.Errorf(`Expected the correct commands to be executed, but got %#v`, **actualCmds)
	}
}

func TestRemoveUserIfNotExisting(t *testing.T) {
	ctx := context.Background()

	runner, _ := MockedRunner()

	subject := BusyboxSyncer{
		Run: runner,
	}

	err := subject.RemoveUser(ctx, "nonexisting")

	if err == nil {
		t.Errorf(`Expected to throw an error but was successful`)
	}
}
