package command

import (
	"bytes"
	"fmt"
	proto "github.com/chremoas/chremoas/proto"
	permsrv "github.com/chremoas/perms-srv/proto"
	"golang.org/x/net/context"
	"strings"
)

type ClientFactory interface {
	NewPermsClient() permsrv.PermissionsClient
}

type command struct {
	funcptr func(ctx context.Context, request *proto.ExecRequest) string
	help    string
}

var cmdName = "perms"
var commandList = map[string]command{
	"list":            {listPermissions, "List all permissions"},
	"list_users":      {listPermissionsUsers, "List users in a permission group"},
	"add":             {addPermission, "Add Permission"},
	"add_user":        {addPermissionUser, "Add users to permission group"},
	"remove":          {removePermission, "Remove Permissions"},
	"remove_user":     {removePermissionUser, "Remove user from permission group"},
	"list_user_perms": {listUserPermissions, "List all the permissions a user has"},
	"notDefined":      {notDefined, ""},
}

var clientFactory ClientFactory

type Command struct {
	//Store anything you need the Help or Exec functions to have access to here
	name    string
	factory ClientFactory
}

func (c *Command) Help(ctx context.Context, req *proto.HelpRequest, rsp *proto.HelpResponse) error {
	rsp.Usage = c.name
	rsp.Description = "Administrate Permissions"
	return nil
}

func (c *Command) Exec(ctx context.Context, req *proto.ExecRequest, rsp *proto.ExecResponse) error {
	var response string

	if req.Args[1] == "help" {
		response = help(ctx, req)
	} else {
		f, ok := commandList[req.Args[1]]
		if ok {
			response = f.funcptr(ctx, req)
		} else {
			response = sendError(fmt.Sprintf("Not a valid subcommand: %s", req.Args[1]))
		}
	}

	rsp.Result = []byte(response)
	return nil
}

func help(ctx context.Context, req *proto.ExecRequest) string {
	var buffer bytes.Buffer

	buffer.WriteString(fmt.Sprintf("Usage: !%s <subcommand> <arguments>\n", cmdName))
	buffer.WriteString("\nSubcommands:\n")

	for cmd := range commandList {
		if commandList[cmd].help != "" {
			buffer.WriteString(fmt.Sprintf("\t%s: %s\n", cmd, commandList[cmd].help))
		}
	}

	return fmt.Sprintf("```%s```", buffer.String())
}

func listPermissions(ctx context.Context, req *proto.ExecRequest) string {
	var buffer bytes.Buffer
	permsClient := clientFactory.NewPermsClient()
	permissions, err := permsClient.ListPermissions(ctx, &permsrv.NilRequest{})

	if err != nil {
		return sendFatal(err.Error())
	}

	buffer.WriteString("Permission Groups:\n")
	for perm := range permissions.PermissionsList {
		buffer.WriteString(fmt.Sprintf("\t%s: %s\n", permissions.PermissionsList[perm].Name, permissions.PermissionsList[perm].Description))
	}

	return fmt.Sprintf("```%s```", buffer.String())
}

func listPermissionsUsers(ctx context.Context, req *proto.ExecRequest) string {
	var buffer bytes.Buffer
	if len(req.Args) != 3 {
		return sendError("Usage: !perms list_users <permission_group>")
	}

	permsClient := clientFactory.NewPermsClient()
	users, err := permsClient.ListPermissionUsers(ctx, &permsrv.UsersRequest{Permission: req.Args[2]})

	if err != nil {
		return sendFatal(err.Error())
	}

	if len(users.UserList) == 0 {
		return sendError("No users in group")
	}

	buffer.WriteString("Permission Users:\n")
	for user := range users.UserList {
		buffer.WriteString(fmt.Sprintf("\t%s\n", users.UserList[user]))
	}

	return fmt.Sprintf("```%s```", buffer.String())
}

func addPermission(ctx context.Context, req *proto.ExecRequest) string {
	if len(req.Args) < 4 {
		return sendError("Usage: !perms add <permission_group> <group_description>")
	}

	name := req.Args[2]
	description := strings.Join(req.Args[3:], " ")

	if len(description) > 0 && description[0] == '"' {
		description = description[1:]
	}

	if len(description) > 0 && description[len(description)-1] == '"' {
		description = description[:len(description)-1]
	}

	canPerform, err := canPerform(ctx, req, []string{"perm_admins"})
	if err != nil {
		return sendFatal(err.Error())
	}

	if !canPerform {
		return sendError("User doesn't have permission to this command")
	}

	permsClient := clientFactory.NewPermsClient()
	_, err = permsClient.AddPermission(ctx, &permsrv.Permission{Name: name, Description: description})
	if err != nil {
		return sendFatal(err.Error())
	}

	return sendSuccess(fmt.Sprintf("Added: %s\n", name))
}

func addPermissionUser(ctx context.Context, req *proto.ExecRequest) string {
	if len(req.Args) < 4 {
		return sendError("Usage: !perms add_user <user> <permission_group>")
	}

	tmp := req.Args[2]
	user := tmp[2 : len(tmp)-1]
	permission := req.Args[3]

	canPerform, err := canPerform(ctx, req, []string{"perm_admins"})
	if err != nil {
		return sendFatal(err.Error())
	}

	if !canPerform {
		return sendError("User doesn't have permission to this command")
	}

	permsClient := clientFactory.NewPermsClient()
	_, err = permsClient.AddPermissionUser(ctx,
		&permsrv.PermissionUser{User: user, Permission: permission})
	if err != nil {
		return sendFatal(err.Error())
	}

	return sendSuccess(fmt.Sprintf("Added '%s' to '%s'\n", user, permission))
}

func removePermission(ctx context.Context, req *proto.ExecRequest) string {
	if len(req.Args) != 3 {
		return sendError("Usage: !perms remove <permission_group>")
	}

	canPerform, err := canPerform(ctx, req, []string{"perm_admins"})
	if err != nil {
		return sendFatal(err.Error())
	}

	if !canPerform {
		return sendError("User doesn't have permission to this command")
	}

	permsClient := clientFactory.NewPermsClient()

	_, err = permsClient.RemovePermission(ctx, &permsrv.Permission{Name: req.Args[2]})
	if err != nil {
		return sendFatal(err.Error())
	}

	return sendSuccess(fmt.Sprintf("Removed: %s\n", req.Args[2]))
}

func removePermissionUser(ctx context.Context, req *proto.ExecRequest) string {
	if len(req.Args) < 4 {
		return sendError("Usage: !perms remove_user <user> <permission_group>")
	}

	canPerform, err := canPerform(ctx, req, []string{"perm_admins"})
	if err != nil {
		return sendFatal(err.Error())
	}

	if !canPerform {
		return sendError("User doesn't have permission to this command")
	}

	tmp := req.Args[2]
	user := tmp[2 : len(tmp)-1]
	permission := req.Args[3]

	permsClient := clientFactory.NewPermsClient()
	_, err = permsClient.RemovePermissionUser(ctx,
		&permsrv.PermissionUser{User: user, Permission: permission})
	if err != nil {
		return sendFatal(err.Error())
	}

	return sendSuccess(fmt.Sprintf("Removed '%s' from '%s'\n", user, permission))
}

func listUserPermissions(ctx context.Context, req *proto.ExecRequest) string {
	var buffer bytes.Buffer
	permsClient := clientFactory.NewPermsClient()
	permissions, err := permsClient.ListUserPermissions(ctx,
		&permsrv.PermissionUser{User: req.Args[2]})

	if err != nil {
		return sendFatal(err.Error())
	}

	buffer.WriteString("Permission Groups:\n")
	for perm := range permissions.PermissionsList {
		buffer.WriteString(fmt.Sprintf("\t%s: %s\n", permissions.PermissionsList[perm].Name, permissions.PermissionsList[perm].Description))
	}

	return fmt.Sprintf("```%s```", buffer.String())
}

func notDefined(ctx context.Context, req *proto.ExecRequest) string {
	return sendError("Command not implemented")
}

func NewCommand(name string, factory ClientFactory) *Command {
	clientFactory = factory
	newCommand := Command{name: name, factory: factory}
	return &newCommand
}

func canPerform(ctx context.Context, req *proto.ExecRequest, perms []string) (bool, error) {
	permsClient := clientFactory.NewPermsClient()

	sender := strings.Split(req.Sender, ":")
	canPerform, err := permsClient.Perform(ctx,
		&permsrv.PermissionsRequest{User: sender[1], PermissionsList: perms})

	if err != nil {
		return false, err
	}
	return canPerform.CanPerform, nil
}

func sendSuccess(message string) string {
	return fmt.Sprintf(":white_check_mark: %s", message)
}

func sendError(message string) string {
	return fmt.Sprintf(":warning: %s", message)
}

func sendFatal(message string) string {
	return fmt.Sprintf(":octagonal_sign: %s", message)
}
