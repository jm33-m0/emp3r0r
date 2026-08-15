STRIP := $(shell command -v x86_64-w64-mingw32-strip 2>/dev/null || echo strip)

all: bof

bof:
	@(mkdir _bin 2>/dev/null) && echo 'creating _bin' || echo '_bin exists'
	@(x86_64-w64-mingw32-gcc -std=gnu11 -w -Wno-incompatible-pointer-types -o _bin/hash.x64.o -I ./ -Os -s -c hash/hash.c && $(STRIP) --strip-unneeded _bin/hash.x64.o) && echo '[*] hash' || echo '[X] hash'
	@(x86_64-w64-mingw32-gcc -std=gnu11 -w -Wno-incompatible-pointer-types -o _bin/klist.x64.o -I ./ -Os -s -c klist/klist.c && $(STRIP) --strip-unneeded _bin/klist.x64.o) && echo '[*] klist' || echo '[X] klist'
	@(x86_64-w64-mingw32-gcc -std=gnu11 -w -Wno-incompatible-pointer-types -o _bin/triage.x64.o -I ./ -DTRIAGE -Os -s -c klist/klist.c && $(STRIP) --strip-unneeded _bin/triage.x64.o) && echo '[*] triage' || echo '[X] triage'
	@(x86_64-w64-mingw32-gcc -std=gnu11 -w -Wno-incompatible-pointer-types -o _bin/dump.x64.o -I ./ -DDUMP -Os -s -c klist/klist.c && $(STRIP) --strip-unneeded _bin/dump.x64.o) && echo '[*] dump' || echo '[X] dump'
	@(x86_64-w64-mingw32-gcc -std=gnu11 -w -Wno-incompatible-pointer-types -o _bin/describe.x64.o -I ./ -Os -s -c describe/describe.c && $(STRIP) --strip-unneeded _bin/describe.x64.o) && echo '[*] describe' || echo '[X] describe'
	@(x86_64-w64-mingw32-gcc -std=gnu11 -w -Wno-incompatible-pointer-types -o _bin/tgtdeleg.x64.o -I ./ -Os -s -c tgtdeleg/tgtdeleg.c && $(STRIP) --strip-unneeded _bin/tgtdeleg.x64.o) && echo '[*] tgtdeleg' || echo '[X] tgtdeleg'
	@(x86_64-w64-mingw32-gcc -std=gnu11 -w -Wno-incompatible-pointer-types -o _bin/ptt.x64.o -I ./ -Os -s -c ptt/ptt.c && $(STRIP) --strip-unneeded _bin/ptt.x64.o) && echo '[*] ptt' || echo '[X] ptt'
	@(x86_64-w64-mingw32-gcc -std=gnu11 -w -Wno-incompatible-pointer-types -o _bin/purge.x64.o -I ./ -Os -s -c purge/purge.c && $(STRIP) --strip-unneeded _bin/purge.x64.o) && echo '[*] purge' || echo '[X] purge'
	@(x86_64-w64-mingw32-gcc -std=gnu11 -w -Wno-incompatible-pointer-types -o _bin/asktgt.x64.o -I ./ -Os -s -c asktgt/asktgt.c && $(STRIP) --strip-unneeded _bin/asktgt.x64.o) && echo '[*] asktgt' || echo '[X] asktgt'
	@(x86_64-w64-mingw32-gcc -std=gnu11 -w -Wno-incompatible-pointer-types -o _bin/asktgs.x64.o -I ./ -Os -s -c asktgs/asktgs.c && $(STRIP) --strip-unneeded _bin/asktgs.x64.o) && echo '[*] asktgs' || echo '[X] asktgs'
	@(x86_64-w64-mingw32-gcc -std=gnu11 -w -Wno-incompatible-pointer-types -o _bin/renew.x64.o -I ./ -Os -s -c renew/renew.c && $(STRIP) --strip-unneeded _bin/renew.x64.o) && echo '[*] renew' || echo '[X] renew'
	@(x86_64-w64-mingw32-gcc -std=gnu11 -w -Wno-incompatible-pointer-types -o _bin/changepw.x64.o -I ./ -Os -s -c changepw/changepw.c && $(STRIP) --strip-unneeded _bin/changepw.x64.o) && echo '[*] changepw' || echo '[X] changepw'
	@(x86_64-w64-mingw32-gcc -std=gnu11 -w -Wno-incompatible-pointer-types -o _bin/asreproasting.x64.o -I ./ -Os -s -c asreproasting/asreproasting.c && $(STRIP) --strip-unneeded _bin/asreproasting.x64.o) && echo '[*] asreproasting' || echo '[X] asreproasting'
	@(x86_64-w64-mingw32-gcc -std=gnu11 -w -Wno-incompatible-pointer-types -o _bin/kerberoasting.x64.o -I ./ -Os -s -c kerberoasting/kerberoasting.c && $(STRIP) --strip-unneeded _bin/kerberoasting.x64.o) && echo '[*] kerberoasting' || echo '[X] kerberoasting'
	@(x86_64-w64-mingw32-gcc -std=gnu11 -w -Wno-incompatible-pointer-types -o _bin/s4u.x64.o -I ./ -Os -s -c s4u/s4u.c && $(STRIP) --strip-unneeded _bin/s4u.x64.o) && echo '[*] s4u' || echo '[X] s4u'
	@(x86_64-w64-mingw32-gcc -std=gnu11 -w -Wno-incompatible-pointer-types -o _bin/cross_s4u.x64.o -I ./ -Os -s -c s4u/cross_s4u.c && $(STRIP) --strip-unneeded _bin/cross_s4u.x64.o) && echo '[*] cross_s4u' || echo '[X] cross_s4u'
