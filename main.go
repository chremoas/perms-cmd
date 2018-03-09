package main

import (
	"fmt"
	permsvc "github.com/chremoas/perms-srv/proto"
	proto "github.com/chremoas/chremoas/proto"
	"github.com/chremoas/perms-cmd/command"
	"github.com/chremoas/services-common/config"
	"github.com/micro/go-micro"
	"github.com/micro/go-micro/client"
)

var Version = "1.0.0"
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
		permsSrv:        config.LookupService("srv", "perms"),
		client:         service.Client()}

	proto.RegisterCommandHandler(service.Server(),
		command.NewCommand(name,
			&clientFactory,
		),
	)

	return nil
}

type clientFactory struct {
	permsSrv        string
	client         client.Client
}

func (c clientFactory) NewPermsClient() permsvc.PermissionsClient {
	return permsvc.NewPermissionsClient(c.permsSrv, c.client)
}
