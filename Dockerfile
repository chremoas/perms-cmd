FROM scratch
MAINTAINER Brian Hechinger <wonko@4amlunch.net>

ADD perms-cmd-linux-amd64 perms-cmd
VOLUME /etc/chremoas

ENTRYPOINT ["/perms-cmd", "--configuration_file", "/etc/chremoas/chremoas.yaml"]
