# -* bash *-

DAEMON=/home/pogo/programming/cpp/packetSensor/debug/src/packetsensor
NAME=packetsensor
PIDFILE="/var/run/${NAME}.pid"
START_OPTS="--start --quiet --background --make-pidfile --pidfile ${PIDFILE} --exec ${DAEMON}"
STOP_OPTS="--stop --pidfile ${PIDFILE}"

test -x $DAEMON || exit 0

case "$1" in
  start)
	echo -n "Starting $NAME "
	start-stop-daemon $START_OPTS
	;;
  stop)
	echo -n "Stopping $NAME "
	start-stop-daemon $STOP_OPTS
	;;
  restart|force-reload)
	echo -n "Restarting $NAME: "
	start-stop-daemon $STOP_OPTS
	sleep 1
	start-stop-daemon $START_OPTS
	;;
  *)
	N=/etc/init.d/$NAME
	echo "Usage: $N {start|stop|restart|force-reload}" >&2
	exit 1
	;;
esac

exit 0