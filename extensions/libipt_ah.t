:INPUT,FORWARD,OUTPUT
-p ah -m ah --ahspi 0;=;OK
-p ah -m ah --ahspi 4294967295;=;OK
-p ah -m ah --ahspi 0:4294967295;-p ah -m ah;OK
-p ah -m ah ! --ahspi 0;=;OK
-p ah -m ah --ahspi -1;;FAIL
-p ah -m ah --ahspi 4294967296;;FAIL
-p ah -m ah --ahspi invalid;;FAIL
-p ah -m ah --ahspi 0:invalid;;FAIL
-m ah --ahspi 0;;FAIL
-m ah --ahspi;;FAIL
-m ah;;FAIL
-p ah -m ah;-p ah -m ah --ahspi 0;FAIL
