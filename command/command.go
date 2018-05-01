package command

import (
	"bytes"
	"fmt"
	proto "github.com/chremoas/chremoas/proto"
	permsrv "github.com/chremoas/perms-srv/proto"
	"github.com/chremoas/services-common/args"
	common "github.com/chremoas/services-common/command"
	"golang.org/x/net/context"
	"strings"
)

type ClientFactory interface {
	NewPermsClient() permsrv.PermissionsService
}

var cmdName = "perms"
var perms *common.Permissions
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
	cmd := args.NewArg(cmdName)
	cmd.Add("list", &args.Command{listPermissions, "List all Permissions"})
	cmd.Add("create", &args.Command{addPermission, "Add Permission"})
	cmd.Add("destroy", &args.Command{removePermission, "Delete Permission"})
	cmd.Add("add", &args.Command{addPermissionUser, "Add user to permission group"})
	cmd.Add("remove", &args.Command{removePermissionUser, "Remove user from permission group"})
	cmd.Add("list_users", &args.Command{listPermissionsUsers, "List users in a permission group"})
	cmd.Add("list_user_perms", &args.Command{listUserPermissions, "List all the permissions a user has"})
	err := cmd.Exec(ctx, req, rsp)

	// I don't 100% love this, but it'll do for now. -brian
	if err != nil {
		rsp.Result = []byte(common.SendError(err.Error()))
	}
	return nil
}

func listPermissions(ctx context.Context, req *proto.ExecRequest) string {
	var buffer bytes.Buffer
	permsClient := clientFactory.NewPermsClient()
	permissions, err := permsClient.ListPermissions(ctx, &permsrv.NilRequest{})

	if err != nil {
		return common.SendFatal(err.Error())
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
		return common.SendError("Usage: !perms list_users <permission_group>")
	}

	permsClient := clientFactory.NewPermsClient()
	users, err := permsClient.ListPermissionUsers(ctx, &permsrv.UsersRequest{Permission: req.Args[2]})

	if err != nil {
		return common.SendFatal(err.Error())
	}

	if len(users.UserList) == 0 {
		return common.SendError("No users in group")
	}

	buffer.WriteString("Permission Users:\n")
	for user := range users.UserList {
		buffer.WriteString(fmt.Sprintf("\t%s\n", users.UserList[user]))
	}

	return fmt.Sprintf("```%s```", buffer.String())
}

func addPermission(ctx context.Context, req *proto.ExecRequest) string {
	if len(req.Args) < 4 {
		return common.SendError("Usage: !perms create <permission_group> <group_description>")
	}

	name := req.Args[2]
	description := strings.Join(req.Args[3:], " ")

	if common.IsDiscordUser(name) {
		return common.SendError("Discord users may not be permissions")
	}

	if common.IsDiscordUser(description) {
		return common.SendError("Discord users may not be descriptions")
	}

	if len(description) > 0 && description[0] == '"' {
		description = description[1:]
	}

	if len(description) > 0 && description[len(description)-1] == '"' {
		description = description[:len(description)-1]
	}

	canPerform, err := perms.CanPerform(ctx, req.Sender)
	if err != nil {
		return common.SendFatal(err.Error())
	}

	if !canPerform {
		return common.SendError("User doesn't have permission to this command")
	}

	permsClient := clientFactory.NewPermsClient()
	_, err = permsClient.AddPermission(ctx, &permsrv.Permission{Name: name, Description: description})
	if err != nil {
		return common.SendFatal(err.Error())
	}

	return common.SendSuccess(fmt.Sprintf("Added: %s\n", name))
}

func addPermissionUser(ctx context.Context, req *proto.ExecRequest) string {
	if len(req.Args) < 4 {
		return common.SendError("Usage: !perms add <user> <permission_group>")
	}

	tmp := req.Args[2]
	user := tmp[2 : len(tmp)-1]
	permission := req.Args[3]

	canPerform, err := perms.CanPerform(ctx, req.Sender)
	if err != nil {
		return common.SendFatal(err.Error())
	}

	if !canPerform {
		return common.SendError("User doesn't have permission to this command")
	}

	permsClient := clientFactory.NewPermsClient()
	_, err = permsClient.AddPermissionUser(ctx,
		&permsrv.PermissionUser{User: user, Permission: permission})
	if err != nil {
		return common.SendFatal(err.Error())
	}

	return common.SendSuccess(fmt.Sprintf("Added '%s' to '%s'\n", user, permission))
}

func removePermission(ctx context.Context, req *proto.ExecRequest) string {
	if len(req.Args) != 3 {
		return common.SendError("Usage: !perms destroy <permission_group>")
	}

	canPerform, err := perms.CanPerform(ctx, req.Sender)
	if err != nil {
		return common.SendFatal(err.Error())
	}

	if !canPerform {
		return common.SendError("User doesn't have permission to this command")
	}

	permsClient := clientFactory.NewPermsClient()

	_, err = permsClient.RemovePermission(ctx, &permsrv.Permission{Name: req.Args[2]})
	if err != nil {
		return common.SendFatal(err.Error())
	}

	return common.SendSuccess(fmt.Sprintf("Removed: %s\n", req.Args[2]))
}

func removePermissionUser(ctx context.Context, req *proto.ExecRequest) string {
	if len(req.Args) < 4 {
		return common.SendError("Usage: !perms remove <user> <permission_group>")
	}

	canPerform, err := perms.CanPerform(ctx, req.Sender)
	if err != nil {
		return common.SendFatal(err.Error())
	}

	if !canPerform {
		return common.SendError("User doesn't have permission to this command")
	}

	tmp := req.Args[2]
	user := tmp[2 : len(tmp)-1]
	permission := req.Args[3]

	permsClient := clientFactory.NewPermsClient()
	_, err = permsClient.RemovePermissionUser(ctx,
		&permsrv.PermissionUser{User: user, Permission: permission})
	if err != nil {
		return common.SendFatal(err.Error())
	}

	return common.SendSuccess(fmt.Sprintf("Removed '%s' from '%s'\n", user, permission))
}

func listUserPermissions(ctx context.Context, req *proto.ExecRequest) string {
	if len(req.Args) < 3 {
		return common.SendError("Usage: !perms list_user_perms <user>")
	}

	var buffer bytes.Buffer
	permsClient := clientFactory.NewPermsClient()
	permissions, err := permsClient.ListUserPermissions(ctx,
		&permsrv.PermissionUser{User: req.Args[2]})

	if err != nil {
		return common.SendFatal(err.Error())
	}

	buffer.WriteString("Permission Groups:\n")
	for perm := range permissions.PermissionsList {
		buffer.WriteString(fmt.Sprintf("\t%s: %s\n", permissions.PermissionsList[perm].Name, permissions.PermissionsList[perm].Description))
	}

	return fmt.Sprintf("```%s```", buffer.String())
}

func NewCommand(name string, factory ClientFactory) *Command {
	clientFactory = factory
	perms = &common.Permissions{Client: clientFactory.NewPermsClient(), PermissionsList: []string{"perms_admins"}}
	return &Command{name: name, factory: factory}
}
