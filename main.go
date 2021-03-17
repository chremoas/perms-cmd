package main

import (
	"fmt"

	proto "github.com/chremoas/chremoas/proto"
	permsvc "github.com/chremoas/perms-srv/proto"
	rolesrv "github.com/chremoas/role-srv/proto"
	"github.com/chremoas/services-common/config"
	chremoasPrometheus "github.com/chremoas/services-common/prometheus"
	"github.com/micro/go-micro"
	"github.com/micro/go-micro/client"
	"go.uber.org/zap"

	"github.com/chremoas/perms-cmd/command"
)

var (
	Version = "SET ME YOU KNOB"
	service micro.Service
	name    = "perms"
	logger  *zap.Logger
)

func main() {
	var err error

	// TODO pick stuff up from the config
	logger, err = zap.NewProduction()
	if err != nil {
		panic(err)
	}
	defer logger.Sync()
	logger.Info("Initialized logger")

	go chremoasPrometheus.PrometheusExporter(logger)

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
