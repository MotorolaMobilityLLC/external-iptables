:INPUT,FORWARD,OUTPUT
-j NFQUEUE;=;OK
-j NFQUEUE --queue-num 0;=;OK
-j NFQUEUE --queue-num 65535;=;OK
-j NFQUEUE --queue-num 65536;;FAIL
-j NFQUEUE --queue-num -1;;FAIL
# it says "NFQUEUE: number of total queues is 0", overflow in NFQUEUE_parse_v1?
# ERROR: cannot load: iptables -A INPUT -j NFQUEUE --queue-balance 0:65535
# -j NFQUEUE --queue-balance 0:65535;=;OK
-j NFQUEUE --queue-balance 0:65536;;FAIL
-j NFQUEUE --queue-balance -1:65535;;FAIL
-j NFQUEUE --queue-num 10 --queue-bypass;=;OK
