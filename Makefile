UNICORN = ./unicorn-1.0.2-win32/unicorn.dll

main:
	gcc -g -Wall -m32 -o 1.exe 1.c $(UNICORN)
	gcc -g -Wall -m32 -o 2.exe 2.c $(UNICORN)
	gcc -g -Wall -m32 -o 3.exe 3.c $(UNICORN)
	gcc -g -Wall -m32 -o 4.exe 4.c $(UNICORN)


ifeq (,$(wildcard ./unicorn.dll))
	cp $(UNICORN) ./
endif

.PHONY: clean
clean:
	-rm *.exe



