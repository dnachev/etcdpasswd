package syncer

import (
	"context"
	"errors"
	"os/user"
	"strconv"
	"strings"

	"github.com/cybozu-go/etcdpasswd"
	"github.com/cybozu-go/well"
)

type CmdRunner func(context.Context, string, ...string) error

// BusyboxSyncer synchronizes with local users/groups of Debian/Ubuntu OS.
type BusyboxSyncer struct {
	Run CmdRunner
}

func DefaultRun(ctx context.Context, name string, args ...string) error {
	return well.CommandContext(ctx, name, args...).Run()
}

func NewBusyboxSyncer() *BusyboxSyncer {
	return &BusyboxSyncer{
		Run: DefaultRun,
	}
}

// LookupUser implements etcdpasswd.Syncer interface.
func (s BusyboxSyncer) LookupUser(ctx context.Context, name string) (*etcdpasswd.User, error) {
	uu, err := user.Lookup(name)
	if err != nil {
		if _, ok := err.(user.UnknownUserError); ok {
			return nil, nil
		}
		return nil, err
	}

	return makeUser(uu)
}

// LookupGroup implements etcdpasswd.Syncer interface.
func (s BusyboxSyncer) LookupGroup(ctx context.Context, name string) (*etcdpasswd.Group, error) {
	gg, err := user.LookupGroup(name)
	if err != nil {
		if _, ok := err.(user.UnknownGroupError); ok {
			return nil, nil
		}
		return nil, err
	}
	gid, err := strconv.Atoi(gg.Gid)
	if err != nil {
		return nil, err
	}

	return &etcdpasswd.Group{Name: gg.Name, GID: gid}, nil
}

// AddUser implements etcdpasswd.Syncer interface.
func (s BusyboxSyncer) AddUser(ctx context.Context, u *etcdpasswd.User) error {
	_, err := user.Lookup(u.Name)
	if err == nil {
		return errors.New("user exists: " + u.Name)
	}

	args := []string{
		"-c", u.DisplayName, "-G", u.Group,
		"-s", u.Shell, "-u", strconv.Itoa(u.UID), "-D",
	}
	args = append(args, u.Name)

	// use background context to ignore cancellation.
	err = s.Run(context.Background(), "adduser", args...)
	if err != nil {
		return err
	}

	if len(u.Groups) > 0 {
		for _, groupName := range u.Groups {
			err = s.Run(context.Background(), "addgroup", u.Name, groupName)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// RemoveUser implements etcdpasswd.Syncer interface.
func (s BusyboxSyncer) RemoveUser(ctx context.Context, name string) error {
	_, err := user.Lookup(name)
	if err != nil {
		return err
	}

	// use background context to ignore cancellation.
	return s.Run(context.Background(), "userdel", "-f", "-r", name)
}

func busyBoxUserMod(runner CmdRunner, args ...string) error {
	return runner(context.Background(), "usermod", args...)
}

// SetDisplayName implements etcdpasswd.Syncer interface.
func (s BusyboxSyncer) SetDisplayName(ctx context.Context, name, displayName string) error {
	return busyBoxUserMod(s.Run, "-c", displayName, name)
}

// SetPrimaryGroup implements etcdpasswd.Syncer interface.
func (s BusyboxSyncer) SetPrimaryGroup(ctx context.Context, name, group string) error {
	return busyBoxUserMod(s.Run, "-g", group, name)
}

// SetSupplementalGroups implements etcdpasswd.Syncer interface.
func (s BusyboxSyncer) SetSupplementalGroups(ctx context.Context, name string, groups []string) error {
	return busyBoxUserMod(s.Run, "-G", strings.Join(groups, ","), name)
}

// SetShell implements etcdpasswd.Syncer interface.
func (s BusyboxSyncer) SetShell(ctx context.Context, name, shell string) error {
	return busyBoxUserMod(s.Run, "-s", shell, name)
}

// SetPubKeys implements etcdpasswd.Syncer interface.
func (s BusyboxSyncer) SetPubKeys(ctx context.Context, name string, pubkeys []string) error {
	uu, err := user.Lookup(name)
	if err != nil {
		return err
	}

	uid, err := strconv.Atoi(uu.Uid)
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(uu.Gid)
	if err != nil {
		return err
	}

	return savePubKeys(uu.HomeDir, uid, gid, pubkeys)
}

// LockPassword implements etcdpasswd.Syncer interface.
func (s BusyboxSyncer) LockPassword(ctx context.Context, name string) error {
	return busyBoxUserMod(s.Run, "-L", name)
}

// AddGroup implements etcdpasswd.Syncer interface.
func (s BusyboxSyncer) AddGroup(ctx context.Context, g etcdpasswd.Group) error {
	_, err := user.LookupGroup(g.Name)
	if err == nil {
		return errors.New("group exists: " + g.Name)
	}

	// use background context to ignore cancellation.
	return s.Run(context.Background(),
		"groupadd", "-g", strconv.Itoa(g.GID), g.Name)
}

// RemoveGroup implements etcdpasswd.Syncer interface.
func (s BusyboxSyncer) RemoveGroup(ctx context.Context, name string) error {
	_, err := user.LookupGroup(name)
	if err != nil {
		return err
	}

	// use background context to ignore cancellation.
	return s.Run(context.Background(), "groupdel", name)
}
