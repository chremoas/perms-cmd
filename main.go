package main

import (
	"fmt"
	proto "github.com/chremoas/chremoas/proto"
	"github.com/chremoas/perms-cmd/command"
	permsvc "github.com/chremoas/perms-srv/proto"
	rolesrv "github.com/chremoas/role-srv/proto"
	"github.com/chremoas/services-common/config"
	"github.com/micro/go-micro"
	"github.com/micro/go-micro/client"
)

var Version = "SET ME YOU KNOB"
var service micro.Service
var name = "perms"

func main() {
	service = config.NewService(Version, "cmd", name, initialize)

	if err := service.Run(); err != nil {
		fmt.Println(err)
	}
}

// This function is a callback from the config.NewService function.  Read those docs
func initialize(config *config.Configuration) error {
	clientFactory := clientFactory{
		permsSrv: config.LookupService("srv", "perms"),
		roleSrv:  config.LookupService("srv", "role"),
		client:   service.Client()}

	proto.RegisterCommandHandler(service.Server(),
		command.NewCommand(name,
			&clientFactory,
		),
	)

	return nil
}

type clientFactory struct {
	permsSrv string
	roleSrv  string
	client   client.Client
}

func (c clientFactory) NewPermsClient() permsvc.PermissionsService {
	return permsvc.NewPermissionsService(c.permsSrv, c.client)
}

func (c clientFactory) NewRolesClient() rolesrv.RolesService {
	return rolesrv.NewRolesService(c.roleSrv, c.client)
}
