all: setup_env up create_context run_dagadaemon

setup_env:
	./setup-env.sh
up:
	sudo docker-compose up -d
down:
	sudo docker-compose down
# TODO better...via admin web ui or else..
create_context:
	dagaclient c 2 ./DAGACothority/poc-dagacothority/public.toml
run_dagadaemon:
	dagadaemon
