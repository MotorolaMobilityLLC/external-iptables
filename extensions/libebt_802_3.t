:INPUT,FORWARD,OUTPUT
--802_3-sap ! 0x0a -j CONTINUE;=;OK
--802_3-type 0x000a -j RETURN;=;OK
