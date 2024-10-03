
# port should be a number from the range <1024, 65535>
PORT=$(( 1024 + ( $$ % ( 65535 - 1024 ))))

UMF_LOG_VAL="level:debug;flush:debug;output:stderr;pid:yes"

echo "Starting ipc_ipcapi_anon_fd CONSUMER on port $PORT ..."
UMF_LOG=$UMF_LOG_VAL ./umf_example_ipc_ipcapi_consumer $PORT &

echo "Waiting 1 sec ..."
sleep 1

echo "Starting ipc_ipcapi_anon_fd PRODUCER on port $PORT ..."
UMF_LOG=$UMF_LOG_VAL ./umf_example_ipc_ipcapi_producer $PORT
