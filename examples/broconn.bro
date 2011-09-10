@load frameworks/communication/listen-clear

redef Communication::listen_port_clear = 47758/tcp;
redef Communication::nodes += {
	["broconn"] = [$host = 127.0.0.1, $connect=F, $ssl=F]
};
