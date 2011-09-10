@load frameworks/communication/listen-clear

redef Communication::listen_port_clear = 47758/tcp;
redef Communication::nodes += {
	["broenum"] = [$host = 127.0.0.1, $events = /enumtest/, $connect=F, $ssl=F]
};

type TestEnum: enum {
	ZERO_VALUE,
	FIRST_VALUE,
	SECOND_VALUE,
	THIRD_VALUE,
	FOURTH_VALUE,
} ;

event enumtest(proto: transport_proto) {
	print fmt("protocol: %s", proto);
}
