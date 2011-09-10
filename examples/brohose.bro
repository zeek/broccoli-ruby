# Depending on whether you want to use encryption or not,
# include "listen-clear" or "listen-ssl":
#
@load frameworks/communication/listen-clear

redef Communication::listen_port_clear = 47758/tcp;
redef Communication::nodes += {
	["brohose"] = [$host = 127.0.0.1, $events = /brohose/, $connect=F, $ssl=F]
};

event brohose(id: string) {
	print fmt("%s %s", id, current_time());
}
